package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marck1391/jsync/internal/config"
)

func TestEditAllowedDestPathsCreatesFile(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "sub", "jsync.yaml") // dir does not exist yet
	changed, err := editAllowedDestPaths(cfgFile, "/srv/inbox", false)
	if err != nil {
		t.Fatalf("editAllowedDestPaths: %v", err)
	}
	if !changed {
		t.Fatal("changed = false on first add")
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.AllowedDestPaths) != 1 || cfg.AllowedDestPaths[0] != "/srv/inbox" {
		t.Fatalf("AllowedDestPaths = %v, want [/srv/inbox]", cfg.AllowedDestPaths)
	}
}

func TestEditAllowedDestPathsPreservesComments(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "jsync.yaml")
	original := "# my daemon\nrole: hub   # stays a hub\nport: 4300\n"
	if err := os.WriteFile(cfgFile, []byte(original), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if _, err := editAllowedDestPaths(cfgFile, "/data/a", false); err != nil {
		t.Fatalf("add a: %v", err)
	}
	if _, err := editAllowedDestPaths(cfgFile, "/data/b", false); err != nil {
		t.Fatalf("add b: %v", err)
	}

	out, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	got := string(out)
	for _, want := range []string{"# my daemon", "# stays a hub", "port: 4300", "/data/a", "/data/b"} {
		if !strings.Contains(got, want) {
			t.Errorf("rewritten config missing %q:\n%s", want, got)
		}
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Role != config.RoleHub || cfg.Port != 4300 {
		t.Errorf("existing keys disturbed: role=%q port=%d", cfg.Role, cfg.Port)
	}
	if len(cfg.AllowedDestPaths) != 2 {
		t.Errorf("AllowedDestPaths = %v, want 2 entries", cfg.AllowedDestPaths)
	}
}

func TestEditAllowedDestPathsDedupAndRemove(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "jsync.yaml")

	if changed, _ := editAllowedDestPaths(cfgFile, "/x", false); !changed {
		t.Fatal("first add should report changed")
	}
	if changed, _ := editAllowedDestPaths(cfgFile, "/x", false); changed {
		t.Fatal("adding an existing path should report unchanged")
	}
	if changed, _ := editAllowedDestPaths(cfgFile, "/x/", false); changed {
		t.Fatal("adding the same path with a trailing slash should dedup")
	}
	if changed, err := editAllowedDestPaths(cfgFile, "/x", true); err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if changed, _ := editAllowedDestPaths(cfgFile, "/x", true); changed {
		t.Fatal("removing an absent path should report unchanged")
	}
	cfg, _ := config.Load(cfgFile)
	if len(cfg.AllowedDestPaths) != 0 {
		t.Errorf("AllowedDestPaths = %v, want empty after remove", cfg.AllowedDestPaths)
	}
}

func TestEditAllowedDestPathsPromotesScalarAndFoldsLegacy(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "jsync.yaml")
	original := "allowed_dest_paths: /scalar/root\nallowed_dest_path: /legacy/root\n"
	if err := os.WriteFile(cfgFile, []byte(original), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if _, err := editAllowedDestPaths(cfgFile, "/new/root", false); err != nil {
		t.Fatalf("edit: %v", err)
	}

	out, _ := os.ReadFile(cfgFile)
	if strings.Contains(string(out), "allowed_dest_path:") && !strings.Contains(string(out), "allowed_dest_paths:") {
		t.Errorf("legacy singular key not dropped:\n%s", out)
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := map[string]bool{}
	for _, p := range cfg.AllowedDestPaths {
		got[p] = true
	}
	for _, want := range []string{"/scalar/root", "/legacy/root", "/new/root"} {
		if !got[want] {
			t.Errorf("AllowedDestPaths %v missing %q", cfg.AllowedDestPaths, want)
		}
	}
}
