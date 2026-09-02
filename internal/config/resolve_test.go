package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePrecedence(t *testing.T) {
	// Isolate from the real environment and working directory.
	t.Setenv("JSYNC_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	wd := t.TempDir()
	orig, _ := os.Getwd()
	if err := os.Chdir(wd); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	// 1. Explicit wins over everything.
	if got, _ := Resolve("/explicit/path.yaml"); got != "/explicit/path.yaml" {
		t.Errorf("explicit: got %q", got)
	}

	// 2. $JSYNC_CONFIG when no explicit path.
	t.Setenv("JSYNC_CONFIG", "/from/env.yaml")
	if got, _ := Resolve(""); got != "/from/env.yaml" {
		t.Errorf("env: got %q", got)
	}
	t.Setenv("JSYNC_CONFIG", "")

	// 3. ./jsync.yaml in the working directory.
	local := filepath.Join(wd, "jsync.yaml")
	if err := os.WriteFile(local, []byte("role: hub\n"), 0o600); err != nil {
		t.Fatalf("write local: %v", err)
	}
	got, found := Resolve("")
	if got != "jsync.yaml" || !found {
		t.Errorf("local: got %q found=%v, want jsync.yaml/true", got, found)
	}
	_ = os.Remove(local)

	// 4. Canonical home under XDG_CONFIG_HOME, returned even though absent.
	got, found = Resolve("")
	want := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "jsync", "config.yaml")
	if got != want {
		t.Errorf("home: got %q, want %q", got, want)
	}
	if found {
		t.Errorf("home: found=true for a file that does not exist")
	}
}
