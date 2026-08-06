package pipeline

import (
	"archive/tar"
	"compress/gzip"
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
// Close the returned reader once done with it (directly, or by draining it
// to EOF); either releases the background goroutine.
func NewArchiveReader(root string) io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeArchive(pw, root))
	}()
	return pr
}

func writeArchive(w io.Writer, root string) error {
	root = filepath.Clean(root)
	baseInfo, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("pipeline: stat %s: %w", root, err)
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	walkErr := walkAndAdd(tw, root, baseInfo)
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

func walkAndAdd(tw *tar.Writer, root string, baseInfo fs.FileInfo) error {
	if !baseInfo.IsDir() {
		return addFileToTar(tw, root, filepath.Base(root), baseInfo)
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
		return addFileToTar(tw, path, filepath.ToSlash(rel), info)
	})
}

func addFileToTar(tw *tar.Writer, absPath, relPath string, info fs.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		// Skipped for now — real symlink handling (tar.TypeSymlink +
		// Linkname) is a small, deliberately deferred addition.
		return nil
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
