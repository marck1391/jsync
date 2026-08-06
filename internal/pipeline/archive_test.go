package pipeline

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
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

	ar := NewArchiveReader(root)
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

func TestNewArchiveReaderSingleFile(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "single.txt")
	if err := os.WriteFile(filePath, []byte("just one file"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	ar := NewArchiveReader(filePath)
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
