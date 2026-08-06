package x3dh

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"sync"
)

// Store holds one node's X3DH material: its static X25519 identity DH key,
// the active Signed PreKey, and a pool of unconsumed One-Time PreKeys.
// Persistence and rotation scheduling belong to Fase 4 (the Daemon); this
// type only tracks in-memory state and is safe for concurrent use.
//
// A node uses the same Store on both sides of X3DH: as the responder
// ("Bob") it hands out Bundle()s; as the initiator ("Alice") it plugs its
// own identityDHPriv into DeriveInitiator against a peer's Bundle. The
// identity DH key is deliberately static (generated once, not rotated) —
// unlike the Signed PreKey and One-Time PreKeys, it's what X3DH's DH1/DH2
// terms use to bind the *long-term* identity into the shared secret; a
// fresh key there would defeat the point (see Fase 3 x3dh.go).
type Store struct {
	identityPub    ed25519.PublicKey
	identityPriv   ed25519.PrivateKey
	identityDHPriv *ecdh.PrivateKey

	mu        sync.Mutex
	signed    *SignedPreKey
	nextOTPID uint32
	otps      map[uint32]*OneTimePreKey

	// pending holds a One-Time PreKey after Bundle() has handed it out but
	// before DeriveResponder has actually consumed it in an X3DH
	// computation — Bundle() can't delete it outright, because
	// DeriveResponder (running later, when Fase 2's first chunk arrives)
	// still needs the private half to complete its side of the DH.
	pending map[uint32]*OneTimePreKey
}

// NewStore creates a Store seeded with a fresh identity DH keypair, one
// Signed PreKey, and otpCount One-Time PreKeys.
func NewStore(identityPub ed25519.PublicKey, identityPriv ed25519.PrivateKey, otpCount int) (*Store, error) {
	identityDHPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("x3dh: generate identity DH key: %w", err)
	}

	signed, err := GenerateSignedPreKey(identityPriv, 1)
	if err != nil {
		return nil, err
	}

	s := &Store{
		identityPub:    identityPub,
		identityPriv:   identityPriv,
		identityDHPriv: identityDHPriv,
		signed:         signed,
		nextOTPID:      1,
		otps:           map[uint32]*OneTimePreKey{},
		pending:        map[uint32]*OneTimePreKey{},
	}
	if err := s.replenishOTPsLocked(otpCount); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) replenishOTPsLocked(count int) error {
	otps, err := GenerateOneTimePreKeys(count, s.nextOTPID)
	if err != nil {
		return err
	}
	for _, otp := range otps {
		s.otps[otp.KeyID] = otp
	}
	s.nextOTPID += uint32(count)
	return nil
}

// ReplenishOneTimePreKeys tops up the pool with count fresh One-Time
// PreKeys — called by Fase 4's bootstrap when RemainingOneTimePreKeys drops
// below a configured threshold.
func (s *Store) ReplenishOneTimePreKeys(count int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.replenishOTPsLocked(count)
}

// RotateSignedPreKey replaces the active Signed PreKey with a freshly
// generated one (Fase 4 §1: rotación periódica).
func (s *Store) RotateSignedPreKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	next, err := GenerateSignedPreKey(s.identityPriv, s.signed.KeyID+1)
	if err != nil {
		return err
	}
	s.signed = next
	return nil
}

// Bundle returns the public material for a handshake response (Fase 1 §3
// step 7), moving one One-Time PreKey (if any remain) from the available
// pool into pending — see the pending field doc for why it isn't deleted
// outright here.
func (s *Store) Bundle() Bundle {
	s.mu.Lock()
	defer s.mu.Unlock()

	b := Bundle{
		IdentityKey:           s.identityPub,
		IdentityDHKey:         s.identityDHPriv.PublicKey(),
		SignedPreKeyID:        s.signed.KeyID,
		SignedPreKey:          s.signed.KeyPair.PublicKey(),
		SignedPreKeySignature: s.signed.Signature,
	}
	for id, otp := range s.otps {
		b.OneTimePreKeyID = id
		b.OneTimePreKey = otp.KeyPair.PublicKey()
		delete(s.otps, id)
		s.pending[id] = otp
		break
	}
	return b
}

// RemainingOneTimePreKeys reports how many unconsumed OTPs are left, so the
// Daemon knows when to call ReplenishOneTimePreKeys (Fase 4 §1).
func (s *Store) RemainingOneTimePreKeys() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.otps)
}
