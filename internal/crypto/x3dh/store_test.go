package x3dh

import (
	"crypto/ed25519"
	"testing"
)

func newTestStore(t *testing.T, otpCount int) *Store {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := NewStore(pub, priv, otpCount)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func TestStoreBundleConsumesOneTimePreKey(t *testing.T) {
	s := newTestStore(t, 2)

	if got := s.RemainingOneTimePreKeys(); got != 2 {
		t.Fatalf("RemainingOneTimePreKeys = %d, want 2", got)
	}

	b1 := s.Bundle()
	if b1.OneTimePreKeyID == 0 {
		t.Fatal("Bundle: expected a One-Time PreKey to be included")
	}
	if got := s.RemainingOneTimePreKeys(); got != 1 {
		t.Fatalf("RemainingOneTimePreKeys after first Bundle = %d, want 1", got)
	}

	b2 := s.Bundle()
	if b2.OneTimePreKeyID == 0 || b2.OneTimePreKeyID == b1.OneTimePreKeyID {
		t.Fatalf("Bundle: expected a distinct One-Time PreKey, got %d then %d", b1.OneTimePreKeyID, b2.OneTimePreKeyID)
	}
	if got := s.RemainingOneTimePreKeys(); got != 0 {
		t.Fatalf("RemainingOneTimePreKeys after second Bundle = %d, want 0", got)
	}

	// Pool exhausted: Bundle must still return valid Identity/Signed keys,
	// just with no One-Time PreKey attached.
	b3 := s.Bundle()
	if b3.OneTimePreKeyID != 0 {
		t.Errorf("Bundle with exhausted pool: OneTimePreKeyID = %d, want 0", b3.OneTimePreKeyID)
	}
	if b3.SignedPreKey == nil {
		t.Error("Bundle with exhausted pool: SignedPreKey must still be populated")
	}
}

func TestStoreRotateSignedPreKeyChangesID(t *testing.T) {
	s := newTestStore(t, 0)

	before := s.Bundle().SignedPreKeyID
	if err := s.RotateSignedPreKey(); err != nil {
		t.Fatalf("RotateSignedPreKey: %v", err)
	}
	after := s.Bundle().SignedPreKeyID

	if after == before {
		t.Errorf("SignedPreKeyID unchanged after rotation: %d", after)
	}
}

func TestStoreReplenishOneTimePreKeys(t *testing.T) {
	s := newTestStore(t, 1)
	s.Bundle() // consume the one seeded OTP

	if got := s.RemainingOneTimePreKeys(); got != 0 {
		t.Fatalf("RemainingOneTimePreKeys before replenish = %d, want 0", got)
	}
	if err := s.ReplenishOneTimePreKeys(3); err != nil {
		t.Fatalf("ReplenishOneTimePreKeys: %v", err)
	}
	if got := s.RemainingOneTimePreKeys(); got != 3 {
		t.Fatalf("RemainingOneTimePreKeys after replenish = %d, want 3", got)
	}
}
