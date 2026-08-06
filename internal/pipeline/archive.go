package pipeline

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// NewArchiveReader walks root and streams it out as a tar.gz over the
// returned io.ReadCloser. The walk and compression happen in a background
// goroutine feeding an io.Pipe, so nothing here ever buffers a whole file
// or the whole archive in memory (Fase 2 §2) — reading from the result
// drives the walk forward one buffer at a time. If root is a single file
// rather than a directory, the archive contains just that one entry.
//
// skip is relPath -> expected sha256 hex digest for files internal/daemon's
// resume support (Fase 2 "recuperación de red") already has a good copy of
// on the receiving end — a file whose current local content still hashes
// to that digest is omitted entirely (no header, no data) instead of being
// re-tarred. Pass nil for a plain, unresumed transfer (every file included,
// exactly today's behavior). A file present in skip whose local content no
// longer matches (edited since the interrupted attempt, or just a false
// positive from a stale caller) is archived normally, not skipped — skip
// only ever omits a file it can positively confirm is already correct on
// the other end.
//
// Close the returned reader once done with it (directly, or by draining it
// to EOF); either releases the background goroutine.
func NewArchiveReader(root string, skip map[string]string) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeArchive(pw, root, skip))
	}()
	return pr
}

func writeArchive(w io.Writer, root string, skip map[string]string) error {
	root = filepath.Clean(root)
	baseInfo, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("pipeline: stat %s: %w", root, err)
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	walkErr := walkAndAdd(tw, root, baseInfo, skip)
	if walkErr != nil {
		// Best-effort close so a partial stream still ends in something
		// gzip/tar readers recognize as "truncated" rather than hanging the
		// reader side forever; the real error is walkErr, returned below.
		_ = tw.Close()
		_ = gz.Close()
		return walkErr
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("pipeline: close tar writer: %w", err)
	}
	return gz.Close()
}

func walkAndAdd(tw *tar.Writer, root string, baseInfo fs.FileInfo, skip map[string]string) error {
	if !baseInfo.IsDir() {
		return addFileToTar(tw, root, filepath.Base(root), baseInfo, skip)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		return addFileToTar(tw, path, filepath.ToSlash(rel), info, skip)
	})
}

func addFileToTar(tw *tar.Writer, absPath, relPath string, info fs.FileInfo, skip map[string]string) error {
	if info.Mode()&os.ModeSymlink != 0 {
		// Skipped for now — real symlink handling (tar.TypeSymlink +
		// Linkname) is a small, deliberately deferred addition.
		return nil
	}

	if !info.IsDir() && len(skip) > 0 {
		if wantHash, ok := skip[relPath]; ok {
			matches, err := fileMatchesHash(absPath, wantHash)
			if err != nil {
				return err
			}
			if matches {
				return nil
			}
		}
	}

	hdr, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("pipeline: tar header for %s: %w", relPath, err)
	}
	hdr.Name = relPath
	if info.IsDir() {
		hdr.Name += "/"
	}

	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("pipeline: write tar header for %s: %w", relPath, err)
	}
	if info.IsDir() {
		return nil
	}

	f, err := os.Open(absPath)
	if err != nil {
		return fmt.Errorf("pipeline: open %s: %w", absPath, err)
	}
	defer f.Close()

	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("pipeline: copy %s into archive: %w", absPath, err)
	}
	return nil
}

// EstimateSendSize walks root the same way NewArchiveReader will and sums
// the on-disk size of every regular file that will actually be archived —
// a lightweight upfront estimate (Fase 2 progress reporting) of what
// NewArchiveReader can only know lazily, one buffer at a time, as it
// streams. It's an estimate, not a guarantee: a file listed in skip is
// assumed to be excluded without re-hashing it here (avoiding a second
// full read of every already-resumed file just to build a progress
// number), so if that file changed since skip was built and ends up
// archived anyway, the real transfer can exceed this estimate — same
// caveat any progress bar built on a size estimate lives with (rsync,
// tar). Uses only os.Lstat, never opens a file, so it stays cheap even
// for large trees.
func EstimateSendSize(root string, skip map[string]string) (int64, error) {
	root = filepath.Clean(root)
	baseInfo, err := os.Lstat(root)
	if err != nil {
		return 0, fmt.Errorf("pipeline: stat %s: %w", root, err)
	}

	if !baseInfo.IsDir() {
		if baseInfo.Mode()&os.ModeSymlink != 0 {
			return 0, nil
		}
		if _, skipped := skip[filepath.Base(root)]; skipped {
			return 0, nil
		}
		return baseInfo.Size(), nil
	}

	var total int64
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." || d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if _, skipped := skip[filepath.ToSlash(rel)]; skipped {
			return nil
		}
		total += info.Size()
		return nil
	})
	if walkErr != nil {
		return 0, fmt.Errorf("pipeline: estimate size of %s: %w", root, walkErr)
	}
	return total, nil
}

// fileMatchesHash reports whether absPath's current content hashes to
// wantHash (hex sha256), streaming the file rather than buffering it.
func fileMatchesHash(absPath, wantHash string) (bool, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return false, fmt.Errorf("pipeline: open %s: %w", absPath, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, fmt.Errorf("pipeline: hash %s: %w", absPath, err)
	}
	return hex.EncodeToString(h.Sum(nil)) == wantHash, nil
}
