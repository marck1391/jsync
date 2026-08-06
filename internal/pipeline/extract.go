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
func ExtractArchive(r io.Reader, sandboxDir string, onFileComplete func(relPath, contentHash string, size int64)) error {
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
		default:
			// Anything else (symlinks, devices, ...) is skipped — matches
			// archive.go not emitting those entry types yet either.
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
