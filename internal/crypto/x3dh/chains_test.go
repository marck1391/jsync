package x3dh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"filesharer/internal/crypto/ratchet"
)

// TestBidirectionalChains derives the pair of directional chains Fase 5's
// Watcher session needs (see internal/daemon.WatchSession and
// cmd/fileshare's buildWatchEncryption) the same way the real orchestration
// will: Alice derives her outbound chain the usual X3DH way, Bob mirrors it
// into his inbound chain via DeriveResponderChains, Bob derives a fresh
// outbound chain from a brand-new ephemeral keypair, and Alice mirrors that
// into her inbound chain reusing her original X3DH ephemeral. It then
// exercises both directions with several messages, interleaved in an order
// that would break a single shared chain (see encrypt.go's Encryption doc
// comment) but must not perturb this design, which uses two.
func TestBidirectionalChains(t *testing.T) {
	responder := newTestStore(t, 1) // "Bob"
	initiator := newTestStore(t, 0) // "Alice"

	bundle := responder.Bundle()

	aliceSK, aliceEphemeralPriv, usedOTPID, err := initiator.DeriveInitiator(bundle)
	if err != nil {
		t.Fatalf("DeriveInitiator: %v", err)
	}
	aliceOut, err := ratchet.InitSending(aliceSK, aliceEphemeralPriv, bundle.SignedPreKey)
	if err != nil {
		t.Fatalf("InitSending (alice outbound): %v", err)
	}

	bobSK, bobIn, err := responder.DeriveResponderChains(initiator.IdentityDHPublicKey(), aliceEphemeralPriv.PublicKey(), usedOTPID)
	if err != nil {
		t.Fatalf("DeriveResponderChains: %v", err)
	}
	if !bytes.Equal(aliceSK, bobSK) {
		t.Fatalf("SK mismatch: alice %x, bob %x", aliceSK, bobSK)
	}

	bobEphemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate bob's fresh ephemeral key: %v", err)
	}
	bobOut, err := ratchet.InitSending(bobSK, bobEphemeralPriv, aliceEphemeralPriv.PublicKey())
	if err != nil {
		t.Fatalf("InitSending (bob outbound): %v", err)
	}

	aliceIn, err := ratchet.InitReceiving(aliceSK, aliceEphemeralPriv, bobEphemeralPriv.PublicKey())
	if err != nil {
		t.Fatalf("InitReceiving (alice inbound): %v", err)
	}

	ad := AssociatedData(initiator.identityPub, responder.identityPub)

	// Interleave both directions — a shared single chain would desync or
	// reuse a nonce here; two independent chains must not.
	aliceMsgs := []string{"alice: hello", "alice: how are you", "alice: bye"}
	bobMsgs := []string{"bob: hi", "bob: doing fine"}

	for i, want := range aliceMsgs {
		ct, seq, err := aliceOut.Encrypt([]byte(want), ad)
		if err != nil {
			t.Fatalf("alice encrypt %d: %v", i, err)
		}
		if seq != uint32(i) {
			t.Fatalf("alice->bob seq = %d, want %d", seq, i)
		}
		if bytes.Contains(ct, []byte(want)) {
			t.Fatalf("ciphertext for %q contains the plaintext verbatim", want)
		}
		got, err := bobIn.Decrypt(ct, ad, seq)
		if err != nil {
			t.Fatalf("bob decrypt %d: %v", i, err)
		}
		if string(got) != want {
			t.Fatalf("bob got %q, want %q", got, want)
		}

		if i < len(bobMsgs) {
			bWant := bobMsgs[i]
			bct, bseq, err := bobOut.Encrypt([]byte(bWant), ad)
			if err != nil {
				t.Fatalf("bob encrypt %d: %v", i, err)
			}
			bgot, err := aliceIn.Decrypt(bct, ad, bseq)
			if err != nil {
				t.Fatalf("alice decrypt %d: %v", i, err)
			}
			if string(bgot) != bWant {
				t.Fatalf("alice got %q, want %q", bgot, bWant)
			}
		}
	}
}

// TestDeriveResponderChainsConsumesOTPOnce mirrors
// TestX3DHOneTimePreKeyIsSingleUse (x3dh_test.go): DeriveResponderChains
// must consume the One-Time PreKey exactly once, same as DeriveResponder —
// a second call for the same handshake material must fail, not silently
// re-derive.
func TestDeriveResponderChainsConsumesOTPOnce(t *testing.T) {
	responder := newTestStore(t, 1)
	initiator := newTestStore(t, 0)

	bundle := responder.Bundle()
	_, ephemeralPriv, usedOTPID, err := initiator.DeriveInitiator(bundle)
	if err != nil {
		t.Fatalf("DeriveInitiator: %v", err)
	}

	if _, _, err := responder.DeriveResponderChains(initiator.IdentityDHPublicKey(), ephemeralPriv.PublicKey(), usedOTPID); err != nil {
		t.Fatalf("first DeriveResponderChains: %v", err)
	}
	if _, _, err := responder.DeriveResponderChains(initiator.IdentityDHPublicKey(), ephemeralPriv.PublicKey(), usedOTPID); err == nil {
		t.Fatal("second DeriveResponderChains with the same OTP ID: expected an error (one-time prekey already consumed)")
	}
}
