package pipeline

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requireSymlinkSupport skips the test if this machine/user can't create
// symlinks — most commonly Windows without Developer Mode enabled (or an
// elevated process), confirmed for real during development: os.Symlink
// there fails with "A required privilege is not held by the client."
// Mirrors the standard library's own convention of skipping
// symlink-dependent tests on a platform/environment that doesn't support
// them, rather than failing.
func requireSymlinkSupport(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	link := filepath.Join(dir, "probe")
	if err := os.Symlink("target", link); err != nil {
		t.Skipf("symlink creation not supported in this environment: %v", err)
	}
}

func TestExtractArchiveRoundTrip(t *testing.T) {
	srcRoot := t.TempDir()
	writeTestTree(t, srcRoot)

	dir := t.TempDir()
	sandbox := filepath.Join(dir, "sandbox")

	ar := NewArchiveReader(srcRoot, nil, nil)
	defer ar.Close()

	completed := map[string]string{}
	sizes := map[string]int64{}
	onFileComplete := func(relPath, hash string, size int64) {
		completed[relPath] = hash
		sizes[relPath] = size
	}
	if err := ExtractArchive(ar, sandbox, onFileComplete, nil); err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}

	for _, rel := range []string{"a.txt", "sub/b.txt", "sub/deeper/c.txt"} {
		got, err := os.ReadFile(filepath.Join(sandbox, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read extracted %s: %v", rel, err)
		}
		want, err := os.ReadFile(filepath.Join(srcRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read source %s: %v", rel, err)
		}
		if string(got) != string(want) {
			t.Errorf("%s content mismatch: got %q, want %q", rel, got, want)
		}

		wantHash := sha256.Sum256(want)
		if completed[rel] != hex.EncodeToString(wantHash[:]) {
			t.Errorf("onFileComplete hash for %s = %q, want %x", rel, completed[rel], wantHash)
		}
		if sizes[rel] != int64(len(want)) {
			t.Errorf("onFileComplete size for %s = %d, want %d", rel, sizes[rel], len(want))
		}
	}
	if len(completed) != 3 {
		t.Errorf("onFileComplete called %d times, want 3: %v", len(completed), completed)
	}
}

// TestExtractArchiveOnFileCompleteSkipsTruncatedFile is the resume
// mechanism's core correctness property on the extraction side: a file
// whose bytes never fully arrived must never be reported via
// onFileComplete, even though earlier, fully-received entries in the same
// stream should be. "a.txt" is small and written first by the walk, so it
// lands well before the truncation point; "z_big.txt" is large enough that
// cutting the stream in half reliably lands inside its data.
func TestExtractArchiveOnFileCompleteSkipsTruncatedFile(t *testing.T) {
	srcRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcRoot, "a.txt"), []byte("small and first"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	big := strings.Repeat("x", 256*1024)
	if err := os.WriteFile(filepath.Join(srcRoot, "z_big.txt"), []byte(big), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	full, err := io.ReadAll(NewArchiveReader(srcRoot, nil, nil))
	if err != nil {
		t.Fatalf("read full archive: %v", err)
	}
	truncated := full[:len(full)/2]

	dir := t.TempDir()
	sandbox := filepath.Join(dir, "sandbox")
	completed := map[string]string{}
	err = ExtractArchive(bytes.NewReader(truncated), sandbox, func(relPath, hash string, size int64) { completed[relPath] = hash }, nil)
	if err == nil {
		t.Fatal("ExtractArchive: expected an error for a truncated stream")
	}

	if _, ok := completed["a.txt"]; !ok {
		t.Error("onFileComplete should have been called for a.txt (fully received before the cut)")
	}
	if _, ok := completed["z_big.txt"]; ok {
		t.Error("onFileComplete should NOT have been called for z_big.txt (cut off mid-copy)")
	}
}

func TestCommitSandboxIntoNewDest(t *testing.T) {
	dir := t.TempDir()
	sandbox := filepath.Join(dir, "sandbox")
	dest := filepath.Join(dir, "final", "dest")

	if err := os.MkdirAll(sandbox, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sandbox, "f.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := CommitSandbox(sandbox, dest); err != nil {
		t.Fatalf("CommitSandbox: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dest, "f.txt"))
	if err != nil {
		t.Fatalf("read committed file: %v", err)
	}
	if string(data) != "v1" {
		t.Errorf("content = %q, want %q", data, "v1")
	}
	if _, err := os.Stat(sandbox); !os.IsNotExist(err) {
		t.Errorf("sandbox %s should no longer exist after commit", sandbox)
	}
}

func TestCommitSandboxReplacesExistingDest(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "dest")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "old.txt"), []byte("old"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	sandbox := filepath.Join(dir, "sandbox")
	if err := os.MkdirAll(sandbox, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sandbox, "new.txt"), []byte("new"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := CommitSandbox(sandbox, dest); err != nil {
		t.Fatalf("CommitSandbox: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dest, "old.txt")); !os.IsNotExist(err) {
		t.Error("old.txt should be gone after replacing dest")
	}
	data, err := os.ReadFile(filepath.Join(dest, "new.txt"))
	if err != nil {
		t.Fatalf("read new.txt: %v", err)
	}
	if string(data) != "new" {
		t.Errorf("new.txt content = %q, want %q", data, "new")
	}
	// No leftover .stale-* directory next to dest.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "dest" && e.Name() != "sandbox" {
			t.Errorf("unexpected leftover entry in %s: %s", dir, e.Name())
		}
	}
}

func TestAbortSandboxRemovesDir(t *testing.T) {
	dir := t.TempDir()
	sandbox := filepath.Join(dir, "sandbox")
	if err := os.MkdirAll(sandbox, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sandbox, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if err := AbortSandbox(sandbox); err != nil {
		t.Fatalf("AbortSandbox: %v", err)
	}
	if _, err := os.Stat(sandbox); !os.IsNotExist(err) {
		t.Error("sandbox should be gone after AbortSandbox")
	}
}

func TestSafeJoinRejectsPathEscape(t *testing.T) {
	base := t.TempDir()
	if _, err := safeJoin(base, "../../etc/passwd"); err == nil {
		t.Fatal("safeJoin: expected error for a path escaping base")
	}
	if got, err := safeJoin(base, "a/b/c.txt"); err != nil {
		t.Fatalf("safeJoin: unexpected error for a legitimate nested path: %v", err)
	} else if filepath.Dir(filepath.Dir(filepath.Dir(got))) != base {
		t.Errorf("safeJoin result %q is not under base %q", got, base)
	}
}

func TestSafeSymlinkTargetRejectsAbsolute(t *testing.T) {
	base := t.TempDir()
	entry := filepath.Join(base, "link")
	// Both spellings must be rejected regardless of which platform this
	// test runs on — Linkname came from whatever platform the sender
	// archived on, not necessarily this one (see looksAbsolute's doc).
	for _, target := range []string{"/etc/passwd", `C:\Windows\System32\config\SAM`} {
		if err := safeSymlinkTarget(base, entry, target); err == nil {
			t.Errorf("safeSymlinkTarget: expected error for absolute target %q", target)
		}
	}
}

func TestSafeSymlinkTargetRejectsEscape(t *testing.T) {
	base := t.TempDir()
	entry := filepath.Join(base, "sub", "link")
	if err := safeSymlinkTarget(base, entry, "../../../../etc/passwd"); err == nil {
		t.Fatal("safeSymlinkTarget: expected error for a target escaping the sandbox")
	}
}

func TestSafeSymlinkTargetAcceptsLegitimate(t *testing.T) {
	base := t.TempDir()
	// A link inside base/sub pointing at a sibling file also inside base —
	// legitimate, common (relative symlinks within the same tree).
	entry := filepath.Join(base, "sub", "link")
	if err := safeSymlinkTarget(base, entry, "../other.txt"); err != nil {
		t.Errorf("safeSymlinkTarget: unexpected error for a legitimate in-tree target: %v", err)
	}
}

// TestExtractArchiveSkipsUnsupportedSymlinkAndContinues is the resume-style
// proof that Fase 2's one deliberate "skip, don't abort" path actually
// works end to end: isSymlinkUnsupported is swapped for a stub that always
// reports true (no real symlink-privilege limitation needed to exercise
// this — same technique internal/daemon's disk-full tests use), and a tar
// stream carrying a symlink followed by a regular file must still land
// that regular file even though the symlink itself can never be created.
func TestExtractArchiveSkipsUnsupportedSymlinkAndContinues(t *testing.T) {
	orig := isSymlinkUnsupported
	isSymlinkUnsupported = func(error) bool { return true }
	defer func() { isSymlinkUnsupported = orig }()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "a-link",
		Typeflag: tar.TypeSymlink,
		Linkname: "somewhere",
		Mode:     0o777,
	}); err != nil {
		t.Fatalf("write symlink header: %v", err)
	}
	content := []byte("still arrives")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "after.txt",
		Typeflag: tar.TypeReg,
		Size:     int64(len(content)),
		Mode:     0o644,
	}); err != nil {
		t.Fatalf("write file header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write file content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}

	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(buf.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	dir := t.TempDir()
	sandbox := filepath.Join(dir, "sandbox")

	// Force writeSymlink's own os.Remove(target) to fail for real,
	// deterministically, regardless of this platform's symlink privileges
	// (on Linux, unlike unprivileged Windows, os.Symlink would otherwise
	// just succeed — proven the hard way running this on the Alpine VM —
	// so isSymlinkUnsupported below would never even get consulted). A
	// non-empty directory can never be removed by a plain os.Remove on any
	// platform. What actually caused the failure doesn't matter: the
	// stubbed classifier below decides it's skip-worthy regardless — the
	// point of this test is that ExtractArchive honors that classifier and
	// keeps going, not what real-world condition would trigger it.
	if err := os.MkdirAll(filepath.Join(sandbox, "a-link", "occupied"), 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sandbox, "a-link", "occupied", "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	var skipped []string
	onSkippedSymlink := func(relPath string, cause error) { skipped = append(skipped, relPath) }
	if err := ExtractArchive(&gzBuf, sandbox, nil, onSkippedSymlink); err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}

	if len(skipped) != 1 || skipped[0] != "a-link" {
		t.Errorf("onSkippedSymlink calls = %v, want exactly [a-link]", skipped)
	}
	got, err := os.ReadFile(filepath.Join(sandbox, "after.txt"))
	if err != nil {
		t.Fatalf("read after.txt: %v (the file after the skipped symlink should still have been extracted)", err)
	}
	if string(got) != string(content) {
		t.Errorf("after.txt content = %q, want %q", got, content)
	}
	info, err := os.Lstat(filepath.Join(sandbox, "a-link"))
	if err != nil {
		t.Fatalf("Lstat a-link: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Error("a-link should not have become a symlink — it was skipped, the pre-existing directory should be untouched")
	}
	if !info.IsDir() {
		t.Error("a-link should still be the pre-existing directory this test set up (skip must leave it alone, not partially remove it)")
	}
}

// TestExtractArchiveSymlinkRoundTrip is the real (not stubbed) path: a
// genuine symlink, archived and extracted for real. Skipped if this
// environment can't create symlinks.
func TestExtractArchiveSymlinkRoundTrip(t *testing.T) {
	requireSymlinkSupport(t)

	srcRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcRoot, "target.txt"), []byte("the real content"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.Symlink("target.txt", filepath.Join(srcRoot, "link.txt")); err != nil {
		t.Fatalf("setup symlink: %v", err)
	}

	dir := t.TempDir()
	sandbox := filepath.Join(dir, "sandbox")

	ar := NewArchiveReader(srcRoot, nil, nil)
	defer ar.Close()
	if err := ExtractArchive(ar, sandbox, nil, nil); err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}

	gotTarget, err := os.Readlink(filepath.Join(sandbox, "link.txt"))
	if err != nil {
		t.Fatalf("Readlink extracted link.txt: %v", err)
	}
	if filepath.ToSlash(gotTarget) != "target.txt" {
		t.Errorf("extracted symlink target = %q, want %q", gotTarget, "target.txt")
	}
	data, err := os.ReadFile(filepath.Join(sandbox, "link.txt")) // follows the link
	if err != nil {
		t.Fatalf("read through extracted symlink: %v", err)
	}
	if string(data) != "the real content" {
		t.Errorf("content through symlink = %q, want %q", data, "the real content")
	}
}
