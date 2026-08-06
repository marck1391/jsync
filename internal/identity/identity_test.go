package identity

import (
	"path/filepath"
	"testing"
)

func TestGenerateSignVerify(t *testing.T) {
	id, err := Generate("test-machine")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	msg := []byte("hello fase 1")
	sig := id.Sign(msg)
	if !Verify(id.PublicKey, msg, sig) {
		t.Fatal("Verify: expected valid signature to verify")
	}
	if Verify(id.PublicKey, []byte("tampered"), sig) {
		t.Fatal("Verify: expected tampered message to fail verification")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "identity.json")

	original, err := Generate("roundtrip-machine")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := original.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path, "unused-since-file-exists")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.MachineID != original.MachineID {
		t.Errorf("MachineID = %q, want %q", loaded.MachineID, original.MachineID)
	}
	if !loaded.PublicKey.Equal(original.PublicKey) {
		t.Error("loaded PublicKey does not match original")
	}

	msg := []byte("roundtrip check")
	if !Verify(loaded.PublicKey, msg, loaded.Sign(msg)) {
		t.Error("loaded identity cannot sign/verify correctly")
	}
}

func TestLoadGeneratesOnFirstBoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")

	id, err := Load(path, "first-boot-machine")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if id.MachineID != "first-boot-machine" {
		t.Errorf("MachineID = %q, want %q", id.MachineID, "first-boot-machine")
	}

	// A second Load must reuse the persisted identity, not generate a new one.
	reloaded, err := Load(path, "ignored")
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if !reloaded.PublicKey.Equal(id.PublicKey) {
		t.Error("second Load generated a different identity instead of reusing the persisted one")
	}
}
