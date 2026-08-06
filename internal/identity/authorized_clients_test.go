package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuthorizedClientsAddIsAuthorized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_clients")

	ac, err := LoadAuthorizedClients(path)
	if err != nil {
		t.Fatalf("LoadAuthorizedClients (missing file): %v", err)
	}

	trusted, err := Generate("trusted-peer")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	stranger, err := Generate("stranger")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if ac.IsAuthorized(trusted.PublicKey) {
		t.Fatal("IsAuthorized: expected false before Add")
	}

	if err := ac.Add(trusted.PublicKey); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !ac.IsAuthorized(trusted.PublicKey) {
		t.Error("IsAuthorized: expected true after Add")
	}
	if ac.IsAuthorized(stranger.PublicKey) {
		t.Error("IsAuthorized: stranger must not be authorized")
	}

	// Persistence: a fresh load from disk must see the same trust list.
	reloaded, err := LoadAuthorizedClients(path)
	if err != nil {
		t.Fatalf("LoadAuthorizedClients (after Add): %v", err)
	}
	if !reloaded.IsAuthorized(trusted.PublicKey) {
		t.Error("reloaded AuthorizedClients lost the trusted key")
	}

	if err := ac.Remove(trusted.PublicKey); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if ac.IsAuthorized(trusted.PublicKey) {
		t.Error("IsAuthorized: expected false after Remove")
	}
}

func TestAuthorizedClientsRejectsInvalidLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_clients")

	if err := os.WriteFile(path, []byte("not-a-valid-base64-key!!\n"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if _, err := LoadAuthorizedClients(path); err == nil {
		t.Fatal("LoadAuthorizedClients: expected error on malformed key line")
	}
}
