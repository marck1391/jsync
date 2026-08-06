package x3dh

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"
)

// SignedPreKey is a rotating X25519 keypair signed by the node's Ed25519
// identity key — the middle piece of X3DH (Fase 3).
type SignedPreKey struct {
	KeyID     uint32
	KeyPair   *ecdh.PrivateKey
	Signature []byte
	CreatedAt time.Time
}

// OneTimePreKey is a single-use X25519 keypair. Consuming one per handshake
// adds forward secrecy to session establishment itself, on top of what the
// Double Ratchet already gives per-chunk afterwards (Fase 3).
type OneTimePreKey struct {
	KeyID   uint32
	KeyPair *ecdh.PrivateKey
}

// Bundle is the public material a node hands out in its Fase 1 handshake
// response so the initiating side can run X3DH without another round trip.
// OneTimePreKeyID == 0 means no One-Time PreKey was included (the pool was
// empty when the bundle was built).
type Bundle struct {
	IdentityKey ed25519.PublicKey
	// IdentityDHKey is the X25519 counterpart to IdentityKey — Ed25519
	// signs, but X3DH's DH1/DH2 need an X25519 point, and there's no
	// stdlib-safe Ed25519-to-X25519 conversion to lean on, so this is a
	// second, separately generated static key rather than a derived one.
	IdentityDHKey         *ecdh.PublicKey
	SignedPreKeyID        uint32
	SignedPreKey          *ecdh.PublicKey
	SignedPreKeySignature []byte
	OneTimePreKeyID       uint32
	OneTimePreKey         *ecdh.PublicKey
}

// GenerateSignedPreKey creates a new Signed PreKey and signs its public half
// with identityPriv.
func GenerateSignedPreKey(identityPriv ed25519.PrivateKey, keyID uint32) (*SignedPreKey, error) {
	kp, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x3dh: generate signed prekey: %w", err)
	}
	sig := ed25519.Sign(identityPriv, kp.PublicKey().Bytes())
	return &SignedPreKey{KeyID: keyID, KeyPair: kp, Signature: sig, CreatedAt: time.Now()}, nil
}

// GenerateOneTimePreKeys creates count new One-Time PreKeys with sequential
// IDs starting at startID.
func GenerateOneTimePreKeys(count int, startID uint32) ([]*OneTimePreKey, error) {
	otps := make([]*OneTimePreKey, 0, count)
	for i := 0; i < count; i++ {
		keyID := startID + uint32(i)
		kp, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("x3dh: generate one-time prekey %d: %w", keyID, err)
		}
		otps = append(otps, &OneTimePreKey{KeyID: keyID, KeyPair: kp})
	}
	return otps, nil
}

// VerifySignedPreKey reports whether sig is a valid identityPub signature
// over signedPreKeyPub. The initiating side must run this before trusting a
// received Bundle (Fase 3 §1: "evita que un Prekey Bundle falso se cuele").
func VerifySignedPreKey(identityPub ed25519.PublicKey, signedPreKeyPub *ecdh.PublicKey, sig []byte) bool {
	return ed25519.Verify(identityPub, signedPreKeyPub.Bytes(), sig)
}
