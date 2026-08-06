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
