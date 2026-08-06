package x3dh

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadStoreGeneratesOnFirstBoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prekeys.json")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	s, err := LoadStore(path, pub, priv, 3)
	if err != nil {
		t.Fatalf("LoadStore (first boot): %v", err)
	}
	if got := s.RemainingOneTimePreKeys(); got != 3 {
		t.Fatalf("RemainingOneTimePreKeys = %d, want 3", got)
	}

	firstBundle := s.Bundle()
	if !VerifySignedPreKey(firstBundle.IdentityKey, firstBundle.SignedPreKey, firstBundle.SignedPreKeySignature) {
		t.Fatal("freshly generated bundle does not verify")
	}
}

func TestLoadStorePersistsAcrossReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prekeys.json")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	original, err := LoadStore(path, pub, priv, 2)
	if err != nil {
		t.Fatalf("LoadStore (first boot): %v", err)
	}
	originalBundle := original.Bundle()
	if err := original.Save(path); err != nil {
		t.Fatalf("Save after consuming a bundle: %v", err)
	}

	reloaded, err := LoadStore(path, pub, priv, 2)
	if err != nil {
		t.Fatalf("LoadStore (reload): %v", err)
	}

	if got := reloaded.RemainingOneTimePreKeys(); got != 1 {
		t.Fatalf("RemainingOneTimePreKeys after reload = %d, want 1 (one already consumed before Save)", got)
	}

	reloadedBundle := reloaded.Bundle()
	if reloadedBundle.SignedPreKeyID != originalBundle.SignedPreKeyID {
		t.Errorf("SignedPreKeyID changed across reload: got %d, want %d", reloadedBundle.SignedPreKeyID, originalBundle.SignedPreKeyID)
	}
	if !reloadedBundle.SignedPreKey.Equal(originalBundle.SignedPreKey) {
		t.Error("SignedPreKey public material changed across reload")
	}
	if reloadedBundle.OneTimePreKeyID == originalBundle.OneTimePreKeyID {
		t.Error("reloaded bundle handed out the same One-Time PreKey ID that was already consumed")
	}
	if !VerifySignedPreKey(reloadedBundle.IdentityKey, reloadedBundle.SignedPreKey, reloadedBundle.SignedPreKeySignature) {
		t.Error("reloaded bundle does not verify")
	}
}

func TestLoadStoreRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "prekeys.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := LoadStore(path, pub, priv, 1); err == nil {
		t.Fatal("LoadStore: expected error on corrupt file")
	}
}
