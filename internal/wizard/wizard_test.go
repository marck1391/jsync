package wizard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marck1391/jsync/internal/config"
)

func TestWriteConfigFreshFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "jsync.yaml")
	a := filepath.Join(dir, "inbox")
	b := filepath.Join(dir, "shared")

	in := inputs{
		ConfigPath:   cfgPath,
		Role:         string(config.RoleHub),
		Host:         "0.0.0.0",
		Port:         4300,
		LeafNodePort: 7500,
		Dirs:         []Dir{{LocalPath: a, Target: "hub:/srv/inbox"}, {LocalPath: b}},
		Aliases:      map[string]string{"vm-01": "MID-1"},
	}

	mid, err := writeConfig(in)
	if err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if mid == "" {
		t.Fatal("expected a generated machine_id")
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if cfg.Role != config.RoleHub || cfg.Host != "0.0.0.0" || cfg.Port != 4300 || cfg.LeafNodePort != 7500 {
		t.Errorf("scalars wrong: role=%q host=%q port=%d leaf=%d", cfg.Role, cfg.Host, cfg.Port, cfg.LeafNodePort)
	}
	if cfg.MachineID != mid {
		t.Errorf("machine_id in file %q != returned %q", cfg.MachineID, mid)
	}
	if len(cfg.AllowedDestPaths) != 2 {
		t.Errorf("AllowedDestPaths = %v, want the two dirs", cfg.AllowedDestPaths)
	}
	if cfg.Nodes["vm-01"] != "MID-1" {
		t.Errorf("Nodes = %v, want vm-01 -> MID-1", cfg.Nodes)
	}
}

func TestWriteConfigPreservesExistingMachineIDAndComments(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "jsync.yaml")
	original := "# hand-written\nmachine_id: KEEP-ME\nrole: hub  # do not touch the words\n"
	if err := os.WriteFile(cfgPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	mid, err := writeConfig(inputs{
		ConfigPath:   cfgPath,
		Role:         string(config.RoleHub),
		Host:         "127.0.0.1",
		Port:         4222,
		LeafNodePort: 7422,
	})
	if err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	if mid != "KEEP-ME" {
		t.Errorf("existing machine_id overwritten: got %q", mid)
	}
	out, _ := os.ReadFile(cfgPath)
	for _, want := range []string{"# hand-written", "# do not touch the words", "machine_id: KEEP-ME"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("rewrite lost %q:\n%s", want, out)
		}
	}
}

func TestWriteConfigPeerWritesHubURL(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "jsync.yaml")
	// Start from a hub config so the switch must also drop leaf_node_port.
	if err := os.WriteFile(cfgPath, []byte("role: hub\nleaf_node_port: 7422\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeConfig(inputs{
		ConfigPath:     cfgPath,
		Role:           string(config.RolePeer),
		Host:           "127.0.0.1",
		Port:           4222,
		HubLeafNodeURL: "nats://hub.example:7422",
	}); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload (peer needs hub_leaf_node_url to validate): %v", err)
	}
	if cfg.Role != config.RolePeer || cfg.HubLeafNodeURL != "nats://hub.example:7422" {
		t.Errorf("peer config wrong: role=%q url=%q", cfg.Role, cfg.HubLeafNodeURL)
	}
	out, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(out), "leaf_node_port:") {
		t.Errorf("peer config should not carry leaf_node_port:\n%s", out)
	}
}

func TestWatchCommands(t *testing.T) {
	dirs := []Dir{
		{LocalPath: "/home/me/project", Target: "vm-01:/srv/project"},
		{LocalPath: "/home/me/notes"}, // no target -> skipped
		{LocalPath: "/home/me/with space", Target: "hub:/dst"},
	}
	got := WatchCommands("/etc/jsync/config.yaml", dirs)
	if len(got) != 2 {
		t.Fatalf("expected 2 commands, got %d: %v", len(got), got)
	}
	if got[0] != "jsync watch --config /etc/jsync/config.yaml /home/me/project vm-01:/srv/project" {
		t.Errorf("cmd[0] = %q", got[0])
	}
	if !strings.Contains(got[1], `"/home/me/with space"`) {
		t.Errorf("path with space not quoted: %q", got[1])
	}
}

func TestWatchCommandsNoConfigPrefix(t *testing.T) {
	got := WatchCommands("", []Dir{{LocalPath: "/a", Target: "n:/b"}})
	if len(got) != 1 || got[0] != "jsync watch /a n:/b" {
		t.Fatalf("got %v", got)
	}
}
