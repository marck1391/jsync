package x3dh

import (
	"crypto/ed25519"
	"sync"
)

// Store holds one node's current prekey material: the active Signed PreKey
// and a pool of unconsumed One-Time PreKeys. Persistence and rotation
// scheduling belong to Fase 4 (the Daemon); this type only tracks in-memory
// state and is safe for concurrent use.
type Store struct {
	identityPub  ed25519.PublicKey
	identityPriv ed25519.PrivateKey

	mu        sync.Mutex
	signed    *SignedPreKey
	nextOTPID uint32
	otps      map[uint32]*OneTimePreKey
}

// NewStore creates a Store seeded with one Signed PreKey and otpCount
// One-Time PreKeys.
func NewStore(identityPub ed25519.PublicKey, identityPriv ed25519.PrivateKey, otpCount int) (*Store, error) {
	signed, err := GenerateSignedPreKey(identityPriv, 1)
	if err != nil {
		return nil, err
	}

	s := &Store{
		identityPub:  identityPub,
		identityPriv: identityPriv,
		signed:       signed,
		nextOTPID:    1,
		otps:         map[uint32]*OneTimePreKey{},
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
// step 7), consuming one One-Time PreKey if any remain.
func (s *Store) Bundle() Bundle {
	s.mu.Lock()
	defer s.mu.Unlock()

	b := Bundle{
		IdentityKey:           s.identityPub,
		SignedPreKeyID:        s.signed.KeyID,
		SignedPreKey:          s.signed.KeyPair.PublicKey(),
		SignedPreKeySignature: s.signed.Signature,
	}
	for id, otp := range s.otps {
		b.OneTimePreKeyID = id
		b.OneTimePreKey = otp.KeyPair.PublicKey()
		delete(s.otps, id)
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
