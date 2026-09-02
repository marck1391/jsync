package x3dh

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"jsync/internal/crypto/ratchet"
)

const (
	skInfo = "X3DH-Signal"
	skSize = 32
)

// DeriveInitiator runs X3DH as the initiating side ("Alice"), using this
// Store's own static identity DH key: verifies bundle's Signed PreKey
// signature, generates a fresh ephemeral X25519 keypair, performs the
// classical X3DH DH1-DH4 computation (Signal spec:
// https://signal.org/docs/specifications/x3dh/), and returns the derived
// shared secret SK. This is a Store method rather than a free function
// taking a raw private key so the identity DH private key never has to
// leave the package.
//
// The returned ephemeralPriv doubles as this session's initial Double
// Ratchet sending key (internal/crypto/ratchet.InitSending expects it) —
// X3DH's ephemeral key and the ratchet's first DH keypair are, by design
// here, the same keypair, so there is no second ephemeral to generate or
// transmit. usedOTPID is 0 if bundle had no One-Time PreKey to consume.
//
// The caller must send ephemeralPriv.PublicKey() and usedOTPID to the
// responder (Fase 2's first chunk headers carry them) — the responder
// cannot derive the same SK without both.
func (s *Store) DeriveInitiator(bundle Bundle) (sk []byte, ephemeralPriv *ecdh.PrivateKey, usedOTPID uint32, err error) {
	if bundle.IdentityDHKey == nil || bundle.SignedPreKey == nil {
		return nil, nil, 0, fmt.Errorf("x3dh: bundle missing identity DH key or signed prekey")
	}
	if !VerifySignedPreKey(bundle.IdentityKey, bundle.SignedPreKey, bundle.SignedPreKeySignature) {
		return nil, nil, 0, fmt.Errorf("x3dh: bundle's signed prekey does not verify against its identity key")
	}

	ephemeralPriv, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("x3dh: generate ephemeral key: %w", err)
	}

	dh1, err := s.identityDHPriv.ECDH(bundle.SignedPreKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("x3dh: DH1: %w", err)
	}
	dh2, err := ephemeralPriv.ECDH(bundle.IdentityDHKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("x3dh: DH2: %w", err)
	}
	dh3, err := ephemeralPriv.ECDH(bundle.SignedPreKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("x3dh: DH3: %w", err)
	}

	material := concat(dh1, dh2, dh3)
	if bundle.OneTimePreKey != nil {
		dh4, err := ephemeralPriv.ECDH(bundle.OneTimePreKey)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("x3dh: DH4: %w", err)
		}
		material = concat(material, dh4)
		usedOTPID = bundle.OneTimePreKeyID
	}

	sk, err = deriveSK(material)
	if err != nil {
		return nil, nil, 0, err
	}
	return sk, ephemeralPriv, usedOTPID, nil
}

// DeriveInitiatorChain runs DeriveInitiator and immediately bootstraps the
// resulting Double Ratchet sending chain — the common case, since nothing
// on the initiator side is done with a bare SK on its own. Returns the
// chain plus what the caller must hand to the responder (Fase 2's first
// chunk headers): the ephemeral public key and which One-Time PreKey ID,
// if any, was used.
func (s *Store) DeriveInitiatorChain(bundle Bundle) (chain *ratchet.Chain, ephemeralPub *ecdh.PublicKey, usedOTPID uint32, err error) {
	sk, ephemeralPriv, usedOTPID, err := s.DeriveInitiator(bundle)
	if err != nil {
		return nil, nil, 0, err
	}
	chain, err = ratchet.InitSending(sk, ephemeralPriv, bundle.SignedPreKey)
	if err != nil {
		return nil, nil, 0, err
	}
	return chain, ephemeralPriv.PublicKey(), usedOTPID, nil
}

// DeriveResponder runs X3DH as the responding side ("Bob"), mirroring
// whatever the initiator computed in DeriveInitiator. initiatorIdentityDHPub
// and ephemeralPub come off Fase 2's first chunk headers; usedOTPID
// identifies (and permanently consumes, from s.pending — see Store's doc
// comment) the One-Time PreKey the initiator says it used, or is 0 if none.
func (s *Store) DeriveResponder(initiatorIdentityDHPub, ephemeralPub *ecdh.PublicKey, usedOTPID uint32) ([]byte, error) {
	sk, _, err := s.deriveResponder(initiatorIdentityDHPub, ephemeralPub, usedOTPID)
	return sk, err
}

// DeriveResponderChain runs DeriveResponder and immediately bootstraps the
// resulting Double Ratchet receiving chain — the common case, and the only
// way to get one without exposing this Store's Signed PreKey private key
// outside the package.
func (s *Store) DeriveResponderChain(initiatorIdentityDHPub, ephemeralPub *ecdh.PublicKey, usedOTPID uint32) (*ratchet.Chain, error) {
	sk, signedPriv, err := s.deriveResponder(initiatorIdentityDHPub, ephemeralPub, usedOTPID)
	if err != nil {
		return nil, err
	}
	return ratchet.InitReceiving(sk, signedPriv, ephemeralPub)
}

// DeriveResponderChains is DeriveResponderChain's Fase 5 counterpart: a
// live Watcher session is bidirectional, so the responder needs a second,
// independent chain for its own outgoing events — not just the one that
// mirrors the initiator's sending chain. That second chain has to be
// seeded by a fresh DH step (a new ephemeral keypair the caller generates
// against ephemeralPub — see ratchet.InitSending), not derived from the
// same dhOut this method already consumes, or the two chains would share
// key material. This method only hands back sk (alongside the mirrored
// receiving chain DeriveResponderChain already provides) so the caller can
// do that second ratchet.InitSending itself; it does not generate the
// fresh keypair or the second chain here, to keep this package's surface
// symmetric with DeriveResponderChain rather than assuming Fase 5's
// specific two-chain shape.
//
// Calls deriveResponder exactly once — like DeriveResponderChain, never
// call both for the same (initiatorIdentityDHPub, ephemeralPub, usedOTPID):
// deriveResponder permanently consumes the One-Time PreKey identified by
// usedOTPID (see Store's pending field), so a second call for the same
// handshake fails with "one-time prekey ... not found".
func (s *Store) DeriveResponderChains(initiatorIdentityDHPub, ephemeralPub *ecdh.PublicKey, usedOTPID uint32) (sk []byte, inbound *ratchet.Chain, err error) {
	sk, signedPriv, err := s.deriveResponder(initiatorIdentityDHPub, ephemeralPub, usedOTPID)
	if err != nil {
		return nil, nil, err
	}
	inbound, err = ratchet.InitReceiving(sk, signedPriv, ephemeralPub)
	if err != nil {
		return nil, nil, err
	}
	return sk, inbound, nil
}

func (s *Store) deriveResponder(initiatorIdentityDHPub, ephemeralPub *ecdh.PublicKey, usedOTPID uint32) (sk []byte, signedPriv *ecdh.PrivateKey, err error) {
	s.mu.Lock()
	signedPriv = s.signed.KeyPair
	var otpPriv *ecdh.PrivateKey
	if usedOTPID != 0 {
		otp, ok := s.pending[usedOTPID]
		if !ok {
			s.mu.Unlock()
			return nil, nil, fmt.Errorf("x3dh: one-time prekey %d not found (already consumed, expired, or never issued)", usedOTPID)
		}
		otpPriv = otp.KeyPair
		delete(s.pending, usedOTPID)
	}
	s.mu.Unlock()

	dh1, err := signedPriv.ECDH(initiatorIdentityDHPub)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh: DH1: %w", err)
	}
	dh2, err := s.identityDHPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh: DH2: %w", err)
	}
	dh3, err := signedPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, nil, fmt.Errorf("x3dh: DH3: %w", err)
	}

	material := concat(dh1, dh2, dh3)
	if otpPriv != nil {
		dh4, err := otpPriv.ECDH(ephemeralPub)
		if err != nil {
			return nil, nil, fmt.Errorf("x3dh: DH4: %w", err)
		}
		material = concat(material, dh4)
	}

	sk, err = deriveSK(material)
	if err != nil {
		return nil, nil, err
	}
	return sk, signedPriv, nil
}

// AssociatedData is the Double Ratchet's AD = IKA || IKB (Fase 3 §"Root
// Key / Chain Key / Message Key"): the two parties' Ed25519 identity keys,
// initiator first, authenticated (via AES-GCM) on every chunk without
// re-transmitting them. Both sides must compute this the same way —
// initiatorIdentityKey first, always — or every chunk will fail to
// decrypt despite SK matching.
func AssociatedData(initiatorIdentityKey, responderIdentityKey ed25519.PublicKey) []byte {
	return concat(initiatorIdentityKey, responderIdentityKey)
}

// IdentityDHPublicKey exposes this Store's static X25519 identity key —
// the initiator sends its own alongside the ephemeral key so the responder
// can compute DH2 without needing anything beyond what Fase 2's first
// chunk already carries.
func (s *Store) IdentityDHPublicKey() *ecdh.PublicKey {
	return s.identityDHPriv.PublicKey()
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func deriveSK(dhOutputs []byte) ([]byte, error) {
	// X3DH spec: prefix a run of 0xFF bytes before the concatenated DH
	// outputs, so the derived key material can never be confused with (or
	// collide in some other protocol's parsing with) any of the raw DH
	// outputs used to build it.
	prefix := make([]byte, 32)
	for i := range prefix {
		prefix[i] = 0xFF
	}

	h := hkdf.New(sha256.New, concat(prefix, dhOutputs), make([]byte, sha256.Size), []byte(skInfo))
	sk := make([]byte, skSize)
	if _, err := io.ReadFull(h, sk); err != nil {
		return nil, fmt.Errorf("x3dh: derive SK: %w", err)
	}
	return sk, nil
}
