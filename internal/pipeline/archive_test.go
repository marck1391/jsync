package pipeline

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestTree(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"a.txt":            "hello from a",
		"sub/b.txt":        "hello from b",
		"sub/deeper/c.txt": "hello from c, nested deeper",
	}
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("setup mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("setup write %s: %v", full, err)
		}
	}
}

func TestNewArchiveReaderDirectory(t *testing.T) {
	root := t.TempDir()
	writeTestTree(t, root)

	ar := NewArchiveReader(root, nil, nil)
	defer ar.Close()

	gz, err := gzip.NewReader(ar)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gz)

	got := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar Next: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar entry %s: %v", hdr.Name, err)
		}
		got[hdr.Name] = string(data)
	}

	want := map[string]string{
		"a.txt":            "hello from a",
		"sub/b.txt":        "hello from b",
		"sub/deeper/c.txt": "hello from c, nested deeper",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %v", len(got), len(want), got)
	}
	for name, content := range want {
		if got[name] != content {
			t.Errorf("entry %s = %q, want %q", name, got[name], content)
		}
	}
}

// readTarEntries drains ar as a tar.gz and returns relPath -> content for
// every regular file entry it finds.
func readTarEntries(t *testing.T, ar io.Reader) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(ar)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gz)

	got := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar Next: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar entry %s: %v", hdr.Name, err)
		}
		got[hdr.Name] = string(data)
	}
	return got
}

func hashOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// TestNewArchiveReaderSkipsMatchingFile confirms the resume path's core
// promise: a file whose current local content still hashes to what skip
// says the receiver already has is omitted from the tar entirely — not
// just re-sent redundantly.
func TestNewArchiveReaderSkipsMatchingFile(t *testing.T) {
	root := t.TempDir()
	writeTestTree(t, root)

	skip := map[string]string{"a.txt": hashOf("hello from a")}

	ar := NewArchiveReader(root, skip, nil)
	defer ar.Close()
	got := readTarEntries(t, ar)

	if _, present := got["a.txt"]; present {
		t.Error("a.txt should have been skipped (matching hash) but appeared in the archive")
	}
	for _, rel := range []string{"sub/b.txt", "sub/deeper/c.txt"} {
		if _, present := got[rel]; !present {
			t.Errorf("%s should still be in the archive (not in skip), but is missing", rel)
		}
	}
}

// TestNewArchiveReaderResendsChangedFile confirms skip only ever omits a
// file it can positively confirm still matches — a stale or wrong hash
// (the local file changed since the interrupted attempt, or the caller
// just got it wrong) must never cause data loss by skipping something the
// receiver doesn't actually have.
func TestNewArchiveReaderResendsChangedFile(t *testing.T) {
	root := t.TempDir()
	writeTestTree(t, root)

	skip := map[string]string{"a.txt": hashOf("this is not a.txt's real content")}

	ar := NewArchiveReader(root, skip, nil)
	defer ar.Close()
	got := readTarEntries(t, ar)

	if got["a.txt"] != "hello from a" {
		t.Errorf("a.txt should have been re-archived (hash mismatch), got %q", got["a.txt"])
	}
}

func TestEstimateSendSizeSumsAllFiles(t *testing.T) {
	root := t.TempDir()
	writeTestTree(t, root)

	want := int64(len("hello from a") + len("hello from b") + len("hello from c, nested deeper"))
	got, err := EstimateSendSize(root, nil, nil)
	if err != nil {
		t.Fatalf("EstimateSendSize: %v", err)
	}
	if got != want {
		t.Errorf("EstimateSendSize = %d, want %d", got, want)
	}
}

func TestEstimateSendSizeExcludesSkippedFiles(t *testing.T) {
	root := t.TempDir()
	writeTestTree(t, root)

	// a.txt is in skip (regardless of hash — EstimateSendSize trusts
	// presence, it doesn't re-hash) — should be excluded from the total.
	skip := map[string]string{"a.txt": "irrelevant-for-this-check"}
	want := int64(len("hello from b") + len("hello from c, nested deeper"))
	got, err := EstimateSendSize(root, skip, nil)
	if err != nil {
		t.Fatalf("EstimateSendSize: %v", err)
	}
	if got != want {
		t.Errorf("EstimateSendSize with skip = %d, want %d", got, want)
	}
}

func TestEstimateSendSizeSingleFile(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "single.txt")
	if err := os.WriteFile(filePath, []byte("just one file"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	got, err := EstimateSendSize(filePath, nil, nil)
	if err != nil {
		t.Fatalf("EstimateSendSize: %v", err)
	}
	if got != int64(len("just one file")) {
		t.Errorf("EstimateSendSize = %d, want %d", got, len("just one file"))
	}
}

// TestNewArchiveReaderEmitsRealSymlinkEntry confirms addSymlinkToTar wrote
// what it's supposed to: a tar.TypeSymlink entry (not skipped, not a
// TypeReg entry with the link's own bytes) carrying the correct Linkname,
// no content. Skipped if this environment can't create symlinks.
func TestNewArchiveReaderEmitsRealSymlinkEntry(t *testing.T) {
	requireSymlinkSupport(t)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "target.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.Symlink("target.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatalf("setup symlink: %v", err)
	}

	ar := NewArchiveReader(root, nil, nil)
	defer ar.Close()

	gz, err := gzip.NewReader(ar)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gz)

	var found *tar.Header
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar Next: %v", err)
		}
		if hdr.Name == "link.txt" {
			h := *hdr
			found = &h
		}
	}

	if found == nil {
		t.Fatal("link.txt entry not found in archive")
	}
	if found.Typeflag != tar.TypeSymlink {
		t.Errorf("link.txt Typeflag = %v, want TypeSymlink", found.Typeflag)
	}
	if found.Linkname != "target.txt" {
		t.Errorf("link.txt Linkname = %q, want %q", found.Linkname, "target.txt")
	}
}

func TestNewArchiveReaderSingleFile(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "single.txt")
	if err := os.WriteFile(filePath, []byte("just one file"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	ar := NewArchiveReader(filePath, nil, nil)
	defer ar.Close()

	gz, err := gzip.NewReader(ar)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	tr := tar.NewReader(gz)

	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("tar Next: %v", err)
	}
	if hdr.Name != "single.txt" {
		t.Errorf("entry name = %q, want %q", hdr.Name, "single.txt")
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	if string(data) != "just one file" {
		t.Errorf("content = %q, want %q", data, "just one file")
	}

	if _, err := tr.Next(); err != io.EOF {
		t.Errorf("expected exactly one entry, got another (or a non-EOF error %v)", err)
	}
}

// prefixMatcher is a minimal PathMatcher stub: matches any relPath under
// (or exactly equal to) one of the given prefixes, gitignore-directory-
// pattern style. Enough to exercise NewArchiveReader/EstimateSendSize's
// exclusion without pulling in internal/ignore's real gitignore parser.
type prefixMatcher []string

func (m prefixMatcher) Match(relPath string) bool {
	for _, prefix := range m {
		if relPath == prefix || strings.HasPrefix(relPath, prefix+"/") {
			return true
		}
	}
	return false
}

// TestNewArchiveReaderExcludesMatchedPaths confirms a non-nil matcher
// keeps a whole excluded subtree out of the archive entirely — not just
// filtered after the fact, but never descended into (mirrors
// internal/watch's own exclusion, and matters in practice for something
// like .jsync/ holding private key material: it must never be walked,
// not merely have its content dropped after being read).
func TestNewArchiveReaderExcludesMatchedPaths(t *testing.T) {
	root := t.TempDir()
	writeTestTree(t, root)
	if err := os.MkdirAll(filepath.Join(root, ".jsync"), 0o755); err != nil {
		t.Fatalf("setup mkdir .jsync: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".jsync", "identity.json"), []byte("private key material"), 0o644); err != nil {
		t.Fatalf("setup write .jsync/identity.json: %v", err)
	}

	ar := NewArchiveReader(root, nil, prefixMatcher{".jsync"})
	defer ar.Close()

	got := readTarEntries(t, ar)
	if _, excluded := got[".jsync/identity.json"]; excluded {
		t.Error(".jsync/identity.json was archived, want it excluded by matcher")
	}
	want := map[string]string{
		"a.txt":            "hello from a",
		"sub/b.txt":        "hello from b",
		"sub/deeper/c.txt": "hello from c, nested deeper",
	}
	for name, content := range want {
		if got[name] != content {
			t.Errorf("entry %s = %q, want %q (non-excluded files must still archive normally)", name, got[name], content)
		}
	}
}

// TestEstimateSendSizeExcludesMatchedPaths mirrors the above for the size
// estimate — an excluded file must not inflate the progress bar's total.
func TestEstimateSendSizeExcludesMatchedPaths(t *testing.T) {
	root := t.TempDir()
	writeTestTree(t, root) // a.txt(12) + sub/b.txt(12) + sub/deeper/c.txt(27) = 51 bytes
	if err := os.MkdirAll(filepath.Join(root, ".jsync"), 0o755); err != nil {
		t.Fatalf("setup mkdir .jsync: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".jsync", "identity.json"), []byte("this should not be counted"), 0o644); err != nil {
		t.Fatalf("setup write .jsync/identity.json: %v", err)
	}

	withMatcher, err := EstimateSendSize(root, nil, prefixMatcher{".jsync"})
	if err != nil {
		t.Fatalf("EstimateSendSize with matcher: %v", err)
	}
	withoutMatcher, err := EstimateSendSize(root, nil, nil)
	if err != nil {
		t.Fatalf("EstimateSendSize without matcher: %v", err)
	}
	if withMatcher != withoutMatcher-int64(len("this should not be counted")) {
		t.Errorf("EstimateSendSize with matcher = %d, want %d (without matcher %d minus the excluded file's size)", withMatcher, withoutMatcher-int64(len("this should not be counted")), withoutMatcher)
	}
}
