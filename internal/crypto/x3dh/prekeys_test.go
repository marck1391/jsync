package x3dh

import (
	"crypto/ed25519"
	"testing"
)

func TestSignedPreKeyVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	spk, err := GenerateSignedPreKey(priv, 1)
	if err != nil {
		t.Fatalf("GenerateSignedPreKey: %v", err)
	}

	if !VerifySignedPreKey(pub, spk.KeyPair.PublicKey(), spk.Signature) {
		t.Fatal("VerifySignedPreKey: expected valid signature to verify")
	}

	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey (other): %v", err)
	}
	if VerifySignedPreKey(otherPub, spk.KeyPair.PublicKey(), spk.Signature) {
		t.Fatal("VerifySignedPreKey: signature must not verify against a different identity key")
	}
}

func TestGenerateOneTimePreKeysSequentialIDs(t *testing.T) {
	otps, err := GenerateOneTimePreKeys(5, 10)
	if err != nil {
		t.Fatalf("GenerateOneTimePreKeys: %v", err)
	}
	if len(otps) != 5 {
		t.Fatalf("len(otps) = %d, want 5", len(otps))
	}
	for i, otp := range otps {
		want := uint32(10 + i)
		if otp.KeyID != want {
			t.Errorf("otps[%d].KeyID = %d, want %d", i, otp.KeyID, want)
		}
	}
}
