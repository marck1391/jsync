package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDestPath(t *testing.T) {
	wd := t.TempDir()
	orig, _ := os.Getwd()
	if err := os.Chdir(wd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	// Relative -> absolute against the current directory.
	got, err := resolveDestPath("aqui")
	if err != nil {
		t.Fatalf("resolveDestPath: %v", err)
	}
	if want := filepath.Join(wd, "aqui"); got != want {
		t.Errorf("resolveDestPath(\"aqui\") = %q, want %q", got, want)
	}

	got, _ = resolveDestPath("./sub/dir")
	if want := filepath.Join(wd, "sub", "dir"); got != want {
		t.Errorf("resolveDestPath(\"./sub/dir\") = %q, want %q", got, want)
	}

	// An already-absolute path (on any platform) passes through verbatim —
	// filepath.Clean would corrupt "/srv/inbox/x" on a Windows client.
	for _, p := range []string{"/srv/inbox/x", `C:\data\x`, "D:/y"} {
		if got, _ := resolveDestPath(p); got != p {
			t.Errorf("resolveDestPath(%q) = %q, want it unchanged", p, got)
		}
	}
}

func TestDestLooksAbsolute(t *testing.T) {
	abs := []string{"/etc/passwd", `\\server\share`, `C:\x`, "D:/y", `\x`}
	rel := []string{"aqui", "./aqui", "../aqui", "a/b/c", "sub:with-colon/y"}
	for _, p := range abs {
		if !destLooksAbsolute(p) {
			t.Errorf("destLooksAbsolute(%q) = false, want true", p)
		}
	}
	for _, p := range rel {
		if destLooksAbsolute(p) {
			t.Errorf("destLooksAbsolute(%q) = true, want false", p)
		}
	}
}
