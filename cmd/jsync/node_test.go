package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jsync/internal/config"
)

func TestEditNodesAddRemove(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "sub", "jsync.yaml") // dir missing

	if changed, err := editNodes(cfgFile, "vm-01", "VM-1", false); err != nil || !changed {
		t.Fatalf("add: changed=%v err=%v", changed, err)
	}
	if changed, _ := editNodes(cfgFile, "vm-01", "VM-1", false); changed {
		t.Fatal("re-adding an identical mapping should report unchanged")
	}
	if changed, err := editNodes(cfgFile, "vm-01", "VM-2", false); err != nil || !changed {
		t.Fatalf("update: changed=%v err=%v", changed, err)
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ResolveNode("vm-01") != "VM-2" {
		t.Errorf("after update, ResolveNode(vm-01) = %q, want VM-2", cfg.ResolveNode("vm-01"))
	}

	if changed, err := editNodes(cfgFile, "vm-01", "", true); err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if changed, _ := editNodes(cfgFile, "vm-01", "", true); changed {
		t.Fatal("removing an absent alias should report unchanged")
	}

	// Removing the last entry drops the `nodes:` key entirely.
	out, _ := os.ReadFile(cfgFile)
	if strings.Contains(string(out), "nodes:") {
		t.Errorf("nodes: key should be gone after removing the last alias:\n%s", out)
	}
}

func TestEditNodesPreservesComments(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "jsync.yaml")
	original := "# my config\nrole: hub\nport: 4300  # fixed\n"
	if err := os.WriteFile(cfgFile, []byte(original), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := editNodes(cfgFile, "hub", "HUB-xyz", false); err != nil {
		t.Fatalf("add hub: %v", err)
	}
	if _, err := editNodes(cfgFile, "build", "BOX-123", false); err != nil {
		t.Fatalf("add build: %v", err)
	}
	out, _ := os.ReadFile(cfgFile)
	got := string(out)
	for _, want := range []string{"# my config", "# fixed", "role: hub", "hub: HUB-xyz", "build: BOX-123"} {
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
	if len(cfg.Nodes) != 2 {
		t.Errorf("Nodes = %v, want 2 entries", cfg.Nodes)
	}
}

func TestValidAlias(t *testing.T) {
	for _, bad := range []string{"", "a:b", "a/b", "a\\b", "a b"} {
		if validAlias(bad) == nil {
			t.Errorf("validAlias(%q) = nil, want error", bad)
		}
	}
	for _, ok := range []string{"vm-01", "hub", "build_box", "a.b"} {
		if err := validAlias(ok); err != nil {
			t.Errorf("validAlias(%q) = %v, want nil", ok, err)
		}
	}
}
