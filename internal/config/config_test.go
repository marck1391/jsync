package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(filepath.Join(dir, "does-not-exist.yaml"))
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
	if !cfg.AuditLog {
		t.Error("AuditLog = false, want true by default")
	}
	// Relative internal defaults resolve against the config file's dir.
	if want := filepath.Join(dir, ".jsync", "audit"); cfg.AuditLogDir != want {
		t.Errorf("AuditLogDir = %q, want %q", cfg.AuditLogDir, want)
	}
	if cfg.Path == "" {
		t.Error("cfg.Path is empty; Load should record the file it read")
	}
}

func TestLoadAuditLogCanBeDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("audit_log: false\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AuditLog {
		t.Error("AuditLog = true, want false when audit_log: false is set")
	}
	// An explicit false must not disturb the directory default.
	if want := filepath.Join(dir, ".jsync", "audit"); cfg.AuditLogDir != want {
		t.Errorf("AuditLogDir = %q, want %q", cfg.AuditLogDir, want)
	}
}

func TestLoadAllowedDestPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	// List form plus the deprecated singular alias, folded together.
	contents := "allowed_dest_paths:\n  - /srv/a\n  - /srv/b\nallowed_dest_path: /srv/legacy\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := map[string]bool{}
	for _, p := range cfg.AllowedDestPaths {
		got[p] = true
	}
	for _, want := range []string{"/srv/a", "/srv/b", "/srv/legacy"} {
		if !got[want] {
			t.Errorf("AllowedDestPaths %v missing %q", cfg.AllowedDestPaths, want)
		}
	}

	// Scalar form.
	if err := os.WriteFile(path, []byte("allowed_dest_paths: /only/one\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatalf("Load scalar: %v", err)
	}
	if len(cfg.AllowedDestPaths) != 1 || cfg.AllowedDestPaths[0] != "/only/one" {
		t.Errorf("scalar allowed_dest_paths = %v, want [/only/one]", cfg.AllowedDestPaths)
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
	// Untouched fields must keep their defaults, resolved against the
	// config file's directory.
	if want := filepath.Join(filepath.Dir(path), ".jsync", "identity.json"); cfg.IdentityPath != want {
		t.Errorf("IdentityPath = %q, want %q", cfg.IdentityPath, want)
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
