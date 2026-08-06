package pipeline

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractArchiveRoundTrip(t *testing.T) {
	srcRoot := t.TempDir()
	writeTestTree(t, srcRoot)

	dir := t.TempDir()
	sandbox := filepath.Join(dir, "sandbox")

	ar := NewArchiveReader(srcRoot)
	defer ar.Close()

	if err := ExtractArchive(ar, sandbox); err != nil {
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
