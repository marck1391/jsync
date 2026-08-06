package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Role != RoleHub {
		t.Errorf("Role = %q, want %q", cfg.Role, RoleHub)
	}
	if cfg.Port != 4222 {
		t.Errorf("Port = %d, want 4222", cfg.Port)
	}
	if cfg.MaxPayloadBytes != 1<<20 {
		t.Errorf("MaxPayloadBytes = %d, want %d", cfg.MaxPayloadBytes, int64(1<<20))
	}
}

func TestLoadParsesYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := `
machine_id: vm-01
role: peer
hub_leaf_node_url: "nats-leaf://10.0.0.5:7422"
max_payload_bytes: 2097152
debug: true
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MachineID != "vm-01" {
		t.Errorf("MachineID = %q, want %q", cfg.MachineID, "vm-01")
	}
	if cfg.Role != RolePeer {
		t.Errorf("Role = %q, want %q", cfg.Role, RolePeer)
	}
	if cfg.HubLeafNodeURL != "nats-leaf://10.0.0.5:7422" {
		t.Errorf("HubLeafNodeURL = %q", cfg.HubLeafNodeURL)
	}
	if cfg.MaxPayloadBytes != 2097152 {
		t.Errorf("MaxPayloadBytes = %d, want 2097152", cfg.MaxPayloadBytes)
	}
	if !cfg.Debug {
		t.Error("Debug = false, want true")
	}
	// Untouched fields must keep their defaults.
	if cfg.IdentityPath != "identity.json" {
		t.Errorf("IdentityPath = %q, want default %q", cfg.IdentityPath, "identity.json")
	}
}

func TestLoadPeerWithoutHubURLFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("role: peer\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load: expected error for role peer without hub_leaf_node_url")
	}
}

func TestLoadUnknownRoleFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("role: nonsense\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load: expected error for unknown role")
	}
}

func TestLoadMalformedYAMLFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("role: [this is not, valid: yaml"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load: expected error for malformed YAML")
	}
}
