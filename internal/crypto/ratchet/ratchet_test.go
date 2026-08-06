package ratchet

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func mustGenKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate X25519 key: %v", err)
	}
	return priv
}

func mustSK(t *testing.T) []byte {
	t.Helper()
	sk := make([]byte, 32)
	if _, err := rand.Read(sk); err != nil {
		t.Fatalf("random SK: %v", err)
	}
	return sk
}

// newTestChainPair mimics how Fase 3 actually wires this: Alice's sending
// chain is seeded from her own ephemeral private key + Bob's Signed
// PreKey public key; Bob's receiving chain is seeded from his Signed
// PreKey private key + Alice's ephemeral public key. Same SK on both
// sides (as x3dh.DeriveInitiator/DeriveResponder guarantee in practice).
func newTestChainPair(t *testing.T) (sending, receiving *Chain) {
	t.Helper()
	sk := mustSK(t)
	aliceEphemeral := mustGenKey(t)
	bobSignedPreKey := mustGenKey(t)

	sending, err := InitSending(sk, aliceEphemeral, bobSignedPreKey.PublicKey())
	if err != nil {
		t.Fatalf("InitSending: %v", err)
	}
	receiving, err = InitReceiving(sk, bobSignedPreKey, aliceEphemeral.PublicKey())
	if err != nil {
		t.Fatalf("InitReceiving: %v", err)
	}
	return sending, receiving
}

func TestInitSendingAndReceivingAgree(t *testing.T) {
	sending, receiving := newTestChainPair(t)
	if !bytes.Equal(sending.key, receiving.key) {
		t.Fatalf("chain keys differ: sending %x, receiving %x", sending.key, receiving.key)
	}
}

func TestChainEncryptDecryptRoundTrip(t *testing.T) {
	sending, receiving := newTestChainPair(t)
	ad := []byte("associated-data-identity-binding")

	plaintexts := []string{"chunk zero", "chunk one is a bit longer", "final chunk"}
	for i, want := range plaintexts {
		ct, seq, err := sending.Encrypt([]byte(want), ad)
		if err != nil {
			t.Fatalf("Encrypt chunk %d: %v", i, err)
		}
		if int(seq) != i {
			t.Fatalf("Encrypt chunk %d: seq = %d, want %d", i, seq, i)
		}

		pt, err := receiving.Decrypt(ct, ad, seq)
		if err != nil {
			t.Fatalf("Decrypt chunk %d: %v", i, err)
		}
		if string(pt) != want {
			t.Errorf("chunk %d = %q, want %q", i, pt, want)
		}
	}
}

func TestChainDecryptRejectsWrongSequence(t *testing.T) {
	sending, receiving := newTestChainPair(t)
	ad := []byte("ad")

	ct, seq, err := sending.Encrypt([]byte("hello"), ad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := receiving.Decrypt(ct, ad, seq+1); err == nil {
		t.Fatal("Decrypt: expected an error for a mismatched sequence number")
	}
	// The chain must not have advanced on a rejected attempt.
	if _, err := receiving.Decrypt(ct, ad, seq); err != nil {
		t.Fatalf("Decrypt with the correct sequence after a rejected one: %v", err)
	}
}

func TestChainDecryptRejectsTamperedCiphertext(t *testing.T) {
	sending, receiving := newTestChainPair(t)
	ad := []byte("ad")

	ct, seq, err := sending.Encrypt([]byte("hello"), ad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ct[0] ^= 0xFF

	if _, err := receiving.Decrypt(ct, ad, seq); err == nil {
		t.Fatal("Decrypt: expected an error for tampered ciphertext")
	}
}

func TestChainDecryptRejectsWrongAssociatedData(t *testing.T) {
	sending, receiving := newTestChainPair(t)

	ct, seq, err := sending.Encrypt([]byte("hello"), []byte("ad-one"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := receiving.Decrypt(ct, []byte("ad-two"), seq); err == nil {
		t.Fatal("Decrypt: expected an error for mismatched associated data")
	}
}

func TestChainKeysEvolvePerMessage(t *testing.T) {
	sending, _ := newTestChainPair(t)
	before := append([]byte(nil), sending.key...)

	if _, _, err := sending.Encrypt([]byte("x"), nil); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(before, sending.key) {
		t.Fatal("chain key did not change after Encrypt — forward secrecy would be broken")
	}
}

func TestDifferentSKsProduceDifferentChains(t *testing.T) {
	aliceEphemeral := mustGenKey(t)
	bobSignedPreKey := mustGenKey(t)

	c1, err := InitSending(mustSK(t), aliceEphemeral, bobSignedPreKey.PublicKey())
	if err != nil {
		t.Fatalf("InitSending: %v", err)
	}
	c2, err := InitSending(mustSK(t), aliceEphemeral, bobSignedPreKey.PublicKey())
	if err != nil {
		t.Fatalf("InitSending: %v", err)
	}
	if bytes.Equal(c1.key, c2.key) {
		t.Fatal("two different SKs produced the same initial chain key")
	}
}
