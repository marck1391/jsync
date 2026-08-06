package x3dh

import (
	"bytes"
	"testing"
)

func TestX3DHBothSidesAgreeWithOneTimePreKey(t *testing.T) {
	responder := newTestStore(t, 3)
	initiator := newTestStore(t, 0)

	bundle := responder.Bundle()
	if bundle.OneTimePreKeyID == 0 {
		t.Fatal("setup: expected the bundle to include a One-Time PreKey")
	}

	initSK, ephemeralPriv, usedOTPID, err := initiator.DeriveInitiator(bundle)
	if err != nil {
		t.Fatalf("DeriveInitiator: %v", err)
	}
	if usedOTPID != bundle.OneTimePreKeyID {
		t.Fatalf("usedOTPID = %d, want %d", usedOTPID, bundle.OneTimePreKeyID)
	}

	respSK, err := responder.DeriveResponder(initiator.IdentityDHPublicKey(), ephemeralPriv.PublicKey(), usedOTPID)
	if err != nil {
		t.Fatalf("DeriveResponder: %v", err)
	}

	if !bytes.Equal(initSK, respSK) {
		t.Fatalf("SK mismatch: initiator %x, responder %x", initSK, respSK)
	}
	if len(initSK) != skSize {
		t.Errorf("SK length = %d, want %d", len(initSK), skSize)
	}
}

func TestX3DHBothSidesAgreeWithoutOneTimePreKey(t *testing.T) {
	responder := newTestStore(t, 0) // empty OTP pool: Bundle() hands out none
	initiator := newTestStore(t, 0)

	bundle := responder.Bundle()
	if bundle.OneTimePreKeyID != 0 {
		t.Fatal("setup: expected no One-Time PreKey in the bundle")
	}

	initSK, ephemeralPriv, usedOTPID, err := initiator.DeriveInitiator(bundle)
	if err != nil {
		t.Fatalf("DeriveInitiator: %v", err)
	}
	if usedOTPID != 0 {
		t.Fatalf("usedOTPID = %d, want 0", usedOTPID)
	}

	respSK, err := responder.DeriveResponder(initiator.IdentityDHPublicKey(), ephemeralPriv.PublicKey(), 0)
	if err != nil {
		t.Fatalf("DeriveResponder: %v", err)
	}

	if !bytes.Equal(initSK, respSK) {
		t.Fatalf("SK mismatch: initiator %x, responder %x", initSK, respSK)
	}
}

func TestX3DHOneTimePreKeyIsSingleUse(t *testing.T) {
	responder := newTestStore(t, 1)
	initiator := newTestStore(t, 0)

	bundle := responder.Bundle()
	_, ephemeralPriv, usedOTPID, err := initiator.DeriveInitiator(bundle)
	if err != nil {
		t.Fatalf("DeriveInitiator: %v", err)
	}

	if _, err := responder.DeriveResponder(initiator.IdentityDHPublicKey(), ephemeralPriv.PublicKey(), usedOTPID); err != nil {
		t.Fatalf("first DeriveResponder: %v", err)
	}

	if _, err := responder.DeriveResponder(initiator.IdentityDHPublicKey(), ephemeralPriv.PublicKey(), usedOTPID); err == nil {
		t.Fatal("second DeriveResponder with the same OTP ID: expected an error (one-time prekey already consumed)")
	}
}

func TestX3DHRejectsUnverifiableBundle(t *testing.T) {
	responder := newTestStore(t, 0)
	initiator := newTestStore(t, 0)

	bundle := responder.Bundle()
	bundle.SignedPreKeySignature = append([]byte(nil), bundle.SignedPreKeySignature...)
	bundle.SignedPreKeySignature[0] ^= 0xFF // tamper

	if _, _, _, err := initiator.DeriveInitiator(bundle); err == nil {
		t.Fatal("DeriveInitiator: expected an error for a bundle with a tampered signature")
	}
}

func TestX3DHDifferentInitiatorsGetDifferentSK(t *testing.T) {
	responder := newTestStore(t, 2)
	alice := newTestStore(t, 0)
	eve := newTestStore(t, 0)

	bundleForAlice := responder.Bundle()
	aliceSK, aliceEph, aliceOTP, err := alice.DeriveInitiator(bundleForAlice)
	if err != nil {
		t.Fatalf("DeriveInitiator (alice): %v", err)
	}
	if _, err := responder.DeriveResponder(alice.IdentityDHPublicKey(), aliceEph.PublicKey(), aliceOTP); err != nil {
		t.Fatalf("DeriveResponder (alice): %v", err)
	}

	bundleForEve := responder.Bundle()
	eveSK, eveEph, eveOTP, err := eve.DeriveInitiator(bundleForEve)
	if err != nil {
		t.Fatalf("DeriveInitiator (eve): %v", err)
	}
	if _, err := responder.DeriveResponder(eve.IdentityDHPublicKey(), eveEph.PublicKey(), eveOTP); err != nil {
		t.Fatalf("DeriveResponder (eve): %v", err)
	}

	if bytes.Equal(aliceSK, eveSK) {
		t.Fatal("two different initiators derived the same SK against the same responder — that should never happen")
	}
}
