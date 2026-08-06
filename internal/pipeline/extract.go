package pipeline

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SandboxPath is the isolated staging directory for sessionID, created in
// the same parent directory as destDir so CommitSandbox's rename is a
// same-volume, instant operation (Fase 4 §Paso 2: "obligatorio que este
// directorio temporal se cree en el mismo volumen físico... que el destino
// final").
func SandboxPath(destDir, sessionID string) string {
	return filepath.Join(filepath.Dir(destDir), ".fileshare_tmp_"+sessionID)
}

// ExtractArchive reads a tar.gz stream from r and writes it into sandboxDir
// (created fresh, or reused — see onFileComplete). It does not commit to
// destDir itself — call CommitSandbox once this returns successfully, or
// AbortSandbox if it returns an error.
//
// onFileComplete, if non-nil, is called with a regular file's relative tar
// path, its sha256 hex digest, and its size, right after that file's bytes
// have been fully copied into sandboxDir — never for a file whose copy is
// cut short by a read/write error (a network drop mid-file never calls it
// for that file). The path+hash is the signal internal/daemon's resume
// support (Fase 2 "recuperación de red") needs to know which files in a
// partially-received sandbox are safe to keep rather than re-request; the
// size is what Fase 2's progress reporting accumulates against
// EstimateSendSize's upfront estimate.
//
// onSkippedSymlink, if non-nil, is called instead of aborting when a
// symlink entry can't be created because isSymlinkUnsupported classifies
// the failure as a platform limitation (most commonly: Windows without
// Developer Mode) rather than a real problem — extraction continues with
// the rest of the tree. This is the one entry-level failure this function
// doesn't treat as fatal; everything else (a corrupt stream, a tar entry
// or symlink target that escapes sandboxDir, an unclassified symlink
// error) still aborts the whole session, same as always.
func ExtractArchive(r io.Reader, sandboxDir string, onFileComplete func(relPath, contentHash string, size int64), onSkippedSymlink func(relPath string, cause error)) error {
	if err := os.MkdirAll(sandboxDir, 0o700); err != nil {
		return fmt.Errorf("pipeline: create sandbox %s: %w", sandboxDir, err)
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("pipeline: open gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("pipeline: read tar entry: %w", err)
		}

		target, err := safeJoin(sandboxDir, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("pipeline: mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("pipeline: mkdir %s: %w", filepath.Dir(target), err)
			}
			hash, size, err := writeRegularFile(target, tr, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if onFileComplete != nil {
				onFileComplete(hdr.Name, hash, size)
			}
		case tar.TypeSymlink:
			// Validates the *target*, not just the entry's own name —
			// safeJoin above already confined where the symlink file
			// itself lives, but says nothing about where it points once
			// followed. This check always aborts on failure, unlike the
			// platform-support check below: an escaping target is a
			// hostile-or-buggy-sender problem, not an environmental one.
			if err := safeSymlinkTarget(sandboxDir, target, hdr.Linkname); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return fmt.Errorf("pipeline: mkdir %s: %w", filepath.Dir(target), err)
			}
			if err := writeSymlink(target, filepath.FromSlash(hdr.Linkname)); err != nil {
				if isSymlinkUnsupported(err) {
					if onSkippedSymlink != nil {
						onSkippedSymlink(hdr.Name, err)
					}
					continue
				}
				return err
			}
		default:
			// Anything else (devices, ...) is skipped — matches archive.go
			// not emitting those entry types.
		}
	}
}

// writeRegularFile copies r into target and returns its sha256 hex digest
// and size, both computed/measured in the same pass (via io.MultiWriter and
// io.Copy's own return value) rather than a separate read or stat afterward.
func writeRegularFile(target string, r io.Reader, mode os.FileMode) (hash string, size int64, err error) {
	if mode == 0 {
		mode = 0o600
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return "", 0, fmt.Errorf("pipeline: create %s: %w", target, err)
	}
	defer f.Close()
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		return "", 0, fmt.Errorf("pipeline: write %s: %w", target, err)
	}
	return hex.EncodeToString(h.Sum(nil)), written, nil
}

// safeJoin joins base and a tar entry name, rejecting one that would
// escape base (e.g. "../../etc/passwd") — a hostile or buggy sender must
// not be able to write outside the sandbox.
func safeJoin(base, name string) (string, error) {
	target := filepath.Join(base, filepath.FromSlash(name))
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("pipeline: tar entry %q escapes sandbox", name)
	}
	return target, nil
}

// safeSymlinkTarget reports whether linkname — a tar entry's raw symlink
// target, exactly as archive.go's addSymlinkToTar wrote it — would still
// resolve inside sandboxDir once actually followed from entryTarget's
// location. safeJoin alone doesn't cover this: it confines where the
// symlink *file* lives, not where it *points*, so without this check a
// perfectly sandbox-confined entry name could still create a symlink
// pointing anywhere on disk (e.g. an absolute "/etc/passwd", or enough
// ".." to walk out). An absolute target is rejected outright — a tree
// meant to be transferred portably between machines has no legitimate
// reason to need one.
func safeSymlinkTarget(sandboxDir, entryTarget, linkname string) error {
	if looksAbsolute(linkname) {
		return fmt.Errorf("pipeline: symlink %q has an absolute target %q, refusing", entryTarget, linkname)
	}
	resolved := filepath.Join(filepath.Dir(entryTarget), filepath.FromSlash(linkname))
	rel, err := filepath.Rel(sandboxDir, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("pipeline: symlink %q target %q escapes sandbox", entryTarget, linkname)
	}
	return nil
}

// looksAbsolute reports whether linkname looks like an absolute path on
// *any* platform, not just whichever one this binary happens to be
// running on. filepath.IsAbs alone isn't enough here: it only recognizes
// the current platform's convention, but Linkname came from whatever
// platform the sender archived on — "/etc/passwd" (POSIX-absolute) must
// be rejected even when this receiver is Windows, where
// filepath.IsAbs("/etc/passwd") is false (Windows absolute paths need a
// drive letter), and a Windows-style "C:\..." target must be rejected
// even on a POSIX receiver.
func looksAbsolute(linkname string) bool {
	if strings.HasPrefix(linkname, "/") || strings.HasPrefix(linkname, "\\") {
		return true
	}
	if len(linkname) >= 2 && linkname[1] == ':' {
		c := linkname[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true // Windows drive-letter path, e.g. "C:\..." or "C:/..."
		}
	}
	return filepath.IsAbs(linkname)
}

// writeSymlink creates a symlink at target pointing to linkname, removing
// whatever (if anything) already sits at target first — sandboxDir can be
// a reused, resumed sandbox (Fase 2 "recuperación de red") where a prior
// attempt's entry might already be there; os.Symlink itself has no
// truncate-and-replace equivalent the way O_TRUNC gives writeRegularFile.
func writeSymlink(target, linkname string) error {
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("pipeline: remove existing %s before symlinking: %w", target, err)
	}
	if err := os.Symlink(linkname, target); err != nil {
		return fmt.Errorf("pipeline: symlink %s -> %s: %w", target, linkname, err)
	}
	return nil
}

// CommitSandbox atomically replaces destDir with sandboxDir's contents
// (Fase 4 §Paso 4). A plain os.Rename is only atomic when destDir doesn't
// already exist or is empty — POSIX rename(2) refuses to replace a
// non-empty directory (ENOTEMPTY), and Windows has an equivalent
// restriction. When destDir already has content, this swaps the old
// content aside first so the rename that actually lands the new content is
// still a single atomic syscall; only the (harmless, and itself atomic)
// cleanup of the old content happens afterward — never before, which is
// what would risk losing destDir's prior contents on a mid-operation crash.
func CommitSandbox(sandboxDir, destDir string) error {
	if err := os.MkdirAll(filepath.Dir(destDir), 0o700); err != nil {
		return fmt.Errorf("pipeline: create parent of %s: %w", destDir, err)
	}

	if _, err := os.Lstat(destDir); err == nil {
		staleDir := destDir + ".stale-" + filepath.Base(sandboxDir)
		if err := os.RemoveAll(staleDir); err != nil { // leftover from a prior crash, if any
			return fmt.Errorf("pipeline: clear stale %s: %w", staleDir, err)
		}
		if err := os.Rename(destDir, staleDir); err != nil {
			return fmt.Errorf("pipeline: move existing %s aside: %w", destDir, err)
		}
		if err := os.Rename(sandboxDir, destDir); err != nil {
			return fmt.Errorf("pipeline: commit %s -> %s: %w", sandboxDir, destDir, err)
		}
		if err := os.RemoveAll(staleDir); err != nil {
			return fmt.Errorf("pipeline: clean up old %s: %w", staleDir, err)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("pipeline: stat %s: %w", destDir, err)
	}

	if err := os.Rename(sandboxDir, destDir); err != nil {
		return fmt.Errorf("pipeline: commit %s -> %s: %w", sandboxDir, destDir, err)
	}
	return nil
}

// AbortSandbox deletes sandboxDir wholesale — Fase 4's garbage-collection
// routine on error or session timeout, returning the destination machine
// to exactly the state it was in before the transfer started.
func AbortSandbox(sandboxDir string) error {
	if err := os.RemoveAll(sandboxDir); err != nil {
		return fmt.Errorf("pipeline: remove sandbox %s: %w", sandboxDir, err)
	}
	return nil
}
