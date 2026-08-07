package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadWithoutFileUsesDefaultsOnly(t *testing.T) {
	root := t.TempDir()
	m, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !m.Match("node_modules/pkg/index.js") {
		t.Error("expected node_modules/... to be matched by default patterns")
	}
	if !m.Match(".git/HEAD") {
		t.Error("expected .git/... to be matched by default patterns")
	}
	if m.Match("src/main.go") {
		t.Error("did not expect src/main.go to be matched")
	}
}

func TestLoadParsesCustomPatterns(t *testing.T) {
	root := t.TempDir()
	contents := "*.log\nsecrets/\n"
	if err := os.WriteFile(filepath.Join(root, FileName), []byte(contents), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	m, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !m.Match("debug.log") {
		t.Error("expected debug.log to match *.log")
	}
	if !m.Match("secrets/api-key.txt") {
		t.Error("expected secrets/api-key.txt to match secrets/")
	}
	if m.Match("readme.md") {
		t.Error("did not expect readme.md to match")
	}
	// Defaults still apply alongside the custom file.
	if !m.Match("node_modules/pkg/index.js") {
		t.Error("expected default patterns to still apply with a custom .fileshareignore present")
	}
}

func TestLoadNegationOverridesDefault(t *testing.T) {
	root := t.TempDir()
	// Un-ignore one specific vendored package while keeping the rest of
	// vendor/ excluded.
	contents := "!vendor/keep-me/\n"
	if err := os.WriteFile(filepath.Join(root, FileName), []byte(contents), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	m, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if m.Match("vendor/keep-me/file.go") {
		t.Error("expected negation to un-ignore vendor/keep-me/")
	}
	if !m.Match("vendor/other/file.go") {
		t.Error("expected vendor/other/ to remain ignored")
	}
}

func TestMatchOnNilMatcherNeverMatches(t *testing.T) {
	var m *Matcher
	if m.Match("anything") {
		t.Error("nil *Matcher should match nothing, not panic or match everything")
	}
}

// TestMatchOnBareDirectoryName confirms a directory-only default pattern
// (e.g. ".fileshare/") matches the bare directory name too, not just
// files nested inside it — the bug this guards against: go-gitignore's
// MatchesPath only recognizes a directory-only pattern against a query
// ending in "/", so without Match's trailing-slash retry, a caller
// deciding whether to filepath.SkipDir an excluded directory (every real
// caller in this project does) would walk into it instead of skipping the
// whole subtree. Found manually: sharing a directory whose default
// identity/prekeys home (.fileshare/) sat inside it left an empty
// .fileshare/ directory at the destination instead of nothing at all.
func TestMatchOnBareDirectoryName(t *testing.T) {
	root := t.TempDir()
	m, err := Load(root)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for _, name := range []string{".fileshare", "node_modules", ".git"} {
		if !m.Match(name) {
			t.Errorf("Match(%q) = false, want true (bare directory name should match its own directory-only default pattern)", name)
		}
	}
	if m.Match("src") {
		t.Error(`Match("src") = true, want false (unrelated bare name must not match)`)
	}
}

// TestLoadSingleFileRoot confirms Load doesn't error when root is a plain
// file rather than a directory — fileshare share supports sharing a single
// file directly. filepath.Join(root, FileName) then trying to read inside
// it fails as ENOTDIR on Linux, which errors.Is(err, os.ErrNotExist)
// does *not* recognize (only ENOENT does — confirmed against a real Linux
// VM), so without Load's explicit os.Stat check this would hard-fail
// there while happening to work on Windows by coincidence of a different
// underlying error. DefaultPatterns should still apply.
func TestLoadSingleFileRoot(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "single.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	m, err := Load(filePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !m.Match("node_modules/pkg/index.js") {
		t.Error("expected default patterns to still apply when root is a single file")
	}
}
