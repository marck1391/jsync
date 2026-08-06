package x3dh

import (
	"encoding/json"
	"testing"
)

func TestBundleJSONRoundTrip(t *testing.T) {
	store := newTestStore(t, 1)
	original := store.Bundle()
	if original.OneTimePreKeyID == 0 {
		t.Fatal("setup: expected a One-Time PreKey in the bundle")
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Bundle
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !decoded.IdentityKey.Equal(original.IdentityKey) {
		t.Error("IdentityKey did not round-trip")
	}
	if decoded.SignedPreKeyID != original.SignedPreKeyID {
		t.Errorf("SignedPreKeyID = %d, want %d", decoded.SignedPreKeyID, original.SignedPreKeyID)
	}
	if decoded.OneTimePreKeyID != original.OneTimePreKeyID {
		t.Errorf("OneTimePreKeyID = %d, want %d", decoded.OneTimePreKeyID, original.OneTimePreKeyID)
	}
	if decoded.SignedPreKey == nil || !decoded.SignedPreKey.Equal(original.SignedPreKey) {
		t.Error("SignedPreKey did not round-trip")
	}
	if decoded.OneTimePreKey == nil || !decoded.OneTimePreKey.Equal(original.OneTimePreKey) {
		t.Error("OneTimePreKey did not round-trip")
	}

	if !VerifySignedPreKey(decoded.IdentityKey, decoded.SignedPreKey, decoded.SignedPreKeySignature) {
		t.Error("VerifySignedPreKey failed on the round-tripped bundle")
	}
}

func TestBundleJSONRoundTripWithoutOneTimePreKey(t *testing.T) {
	store := newTestStore(t, 0)
	original := store.Bundle()
	if original.OneTimePreKeyID != 0 {
		t.Fatal("setup: expected no One-Time PreKey in the bundle")
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Bundle
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.OneTimePreKey != nil {
		t.Error("OneTimePreKey should decode as nil when absent from the bundle")
	}
	if decoded.SignedPreKey == nil {
		t.Error("SignedPreKey must still be present")
	}
}
