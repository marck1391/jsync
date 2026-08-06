package x3dh

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type otpFile struct {
	KeyID      uint32 `json:"key_id"`
	PrivateKey []byte `json:"private_key"`
}

type storeFile struct {
	SignedPreKeyID        uint32    `json:"signed_prekey_id"`
	SignedPreKeyPrivate   []byte    `json:"signed_prekey_private"`
	SignedPreKeySignature []byte    `json:"signed_prekey_signature"`
	SignedPreKeyCreatedAt time.Time `json:"signed_prekey_created_at"`
	NextOTPID             uint32    `json:"next_otp_id"`
	OneTimePreKeys        []otpFile `json:"one_time_prekeys"`
}

// LoadStore reads a Store's prekey material from path. If path does not
// exist yet, it generates a fresh Store (one Signed PreKey, otpCount
// One-Time PreKeys) and persists it first — the same first-boot bootstrap
// pattern as identity.Load (Fase 4 §1).
func LoadStore(path string, identityPub ed25519.PublicKey, identityPriv ed25519.PrivateKey, otpCount int) (*Store, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s, genErr := NewStore(identityPub, identityPriv, otpCount)
		if genErr != nil {
			return nil, genErr
		}
		if saveErr := s.Save(path); saveErr != nil {
			return nil, saveErr
		}
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("x3dh: read %s: %w", path, err)
	}

	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("x3dh: decode %s: %w", path, err)
	}

	signedPriv, err := ecdh.X25519().NewPrivateKey(f.SignedPreKeyPrivate)
	if err != nil {
		return nil, fmt.Errorf("x3dh: decode signed prekey private key: %w", err)
	}

	otps := make(map[uint32]*OneTimePreKey, len(f.OneTimePreKeys))
	for _, of := range f.OneTimePreKeys {
		priv, err := ecdh.X25519().NewPrivateKey(of.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("x3dh: decode one-time prekey %d private key: %w", of.KeyID, err)
		}
		otps[of.KeyID] = &OneTimePreKey{KeyID: of.KeyID, KeyPair: priv}
	}

	return &Store{
		identityPub:  identityPub,
		identityPriv: identityPriv,
		signed: &SignedPreKey{
			KeyID:     f.SignedPreKeyID,
			KeyPair:   signedPriv,
			Signature: f.SignedPreKeySignature,
			CreatedAt: f.SignedPreKeyCreatedAt,
		},
		nextOTPID: f.NextOTPID,
		otps:      otps,
	}, nil
}

// Save persists s's private prekey material to path with owner-only
// permissions, mirroring identity.Identity.Save.
func (s *Store) Save(path string) error {
	s.mu.Lock()
	f := storeFile{
		SignedPreKeyID:        s.signed.KeyID,
		SignedPreKeyPrivate:   s.signed.KeyPair.Bytes(),
		SignedPreKeySignature: s.signed.Signature,
		SignedPreKeyCreatedAt: s.signed.CreatedAt,
		NextOTPID:             s.nextOTPID,
		OneTimePreKeys:        make([]otpFile, 0, len(s.otps)),
	}
	for _, otp := range s.otps {
		f.OneTimePreKeys = append(f.OneTimePreKeys, otpFile{KeyID: otp.KeyID, PrivateKey: otp.KeyPair.Bytes()})
	}
	s.mu.Unlock()

	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("x3dh: encode: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("x3dh: create dir %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("x3dh: write %s: %w", path, err)
	}
	return nil
}
