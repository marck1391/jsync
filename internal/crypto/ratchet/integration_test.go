package ratchet_test

import (
	"testing"

	"github.com/marck1391/jsync/internal/crypto/x3dh"
	"github.com/marck1391/jsync/internal/identity"
)

// TestX3DHBootstrapsMatchingRatchetChains simulates the full Fase 3 flow
// this package and x3dh are designed to compose into: the responder hands
// out a Bundle (as it would in a Fase 1 handshake response), the initiator
// runs X3DH against it and starts encrypting chunks immediately, and the
// responder — armed with only what the initiator would send over Fase 2's
// first chunk headers (its identity DH key, ephemeral key, and which
// One-Time PreKey it used) — derives the identical chain and decrypts them.
func TestX3DHBootstrapsMatchingRatchetChains(t *testing.T) {
	responderIdentity, err := identity.Generate("responder")
	if err != nil {
		t.Fatalf("Generate responder identity: %v", err)
	}
	responderStore, err := x3dh.NewStore(responderIdentity.PublicKey, responderIdentity.PrivateKey, 1)
	if err != nil {
		t.Fatalf("responder x3dh.NewStore: %v", err)
	}

	initiatorIdentity, err := identity.Generate("initiator")
	if err != nil {
		t.Fatalf("Generate initiator identity: %v", err)
	}
	initiatorStore, err := x3dh.NewStore(initiatorIdentity.PublicKey, initiatorIdentity.PrivateKey, 0)
	if err != nil {
		t.Fatalf("initiator x3dh.NewStore: %v", err)
	}

	// Fase 1: the responder's handshake response carries this bundle.
	bundle := responderStore.Bundle()

	// The initiator runs X3DH the moment it has the bundle (no extra round
	// trip) and gets a ready-to-use sending chain back directly.
	sendChain, ephemeralPub, usedOTPID, err := initiatorStore.DeriveInitiatorChain(bundle)
	if err != nil {
		t.Fatalf("DeriveInitiatorChain: %v", err)
	}
	ad := append(append([]byte{}, initiatorIdentity.PublicKey...), responderIdentity.PublicKey...)

	// Fase 2's first chunk headers would carry exactly these: the
	// initiator's static identity DH key, its fresh ephemeral public key,
	// and which One-Time PreKey (if any) it consumed.
	recvChain, err := responderStore.DeriveResponderChain(initiatorStore.IdentityDHPublicKey(), ephemeralPub, usedOTPID)
	if err != nil {
		t.Fatalf("DeriveResponderChain: %v", err)
	}

	chunks := []string{
		"the quick brown fox",
		"jumps over the lazy dog",
		"and this is the final chunk",
	}
	for i, plaintext := range chunks {
		ct, seq, err := sendChain.Encrypt([]byte(plaintext), ad)
		if err != nil {
			t.Fatalf("Encrypt chunk %d: %v", i, err)
		}
		pt, err := recvChain.Decrypt(ct, ad, seq)
		if err != nil {
			t.Fatalf("Decrypt chunk %d: %v", i, err)
		}
		if string(pt) != plaintext {
			t.Errorf("chunk %d = %q, want %q", i, pt, plaintext)
		}
	}
}
