package x3dh

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// bundleWire is Bundle's JSON wire shape. Bundle itself can't rely on
// encoding/json's default struct handling because *ecdh.PublicKey has no
// exported fields — it must be reduced to its raw bytes (via Bytes()) and
// reconstructed (via X25519().NewPublicKey()) by hand.
type bundleWire struct {
	IdentityKey           []byte `json:"identity_key"`
	IdentityDHKey         []byte `json:"identity_dh_key"`
	SignedPreKeyID        uint32 `json:"signed_prekey_id"`
	SignedPreKey          []byte `json:"signed_prekey"`
	SignedPreKeySignature []byte `json:"signed_prekey_signature"`
	OneTimePreKeyID       uint32 `json:"one_time_prekey_id,omitempty"`
	OneTimePreKey         []byte `json:"one_time_prekey,omitempty"`
}

// MarshalJSON implements json.Marshaler for Bundle (Fase 1 §3 step 4: the
// handshake response carries this bundle over NATS as JSON).
func (b Bundle) MarshalJSON() ([]byte, error) {
	w := bundleWire{
		IdentityKey:           b.IdentityKey,
		SignedPreKeyID:        b.SignedPreKeyID,
		SignedPreKeySignature: b.SignedPreKeySignature,
		OneTimePreKeyID:       b.OneTimePreKeyID,
	}
	if b.IdentityDHKey != nil {
		w.IdentityDHKey = b.IdentityDHKey.Bytes()
	}
	if b.SignedPreKey != nil {
		w.SignedPreKey = b.SignedPreKey.Bytes()
	}
	if b.OneTimePreKey != nil {
		w.OneTimePreKey = b.OneTimePreKey.Bytes()
	}
	return json.Marshal(w)
}

// UnmarshalJSON implements json.Unmarshaler for Bundle.
func (b *Bundle) UnmarshalJSON(data []byte) error {
	var w bundleWire
	if err := json.Unmarshal(data, &w); err != nil {
		return fmt.Errorf("x3dh: decode bundle: %w", err)
	}

	b.IdentityKey = ed25519.PublicKey(w.IdentityKey)
	b.SignedPreKeyID = w.SignedPreKeyID
	b.SignedPreKeySignature = w.SignedPreKeySignature
	b.OneTimePreKeyID = w.OneTimePreKeyID
	b.IdentityDHKey = nil
	b.SignedPreKey = nil
	b.OneTimePreKey = nil

	if len(w.IdentityDHKey) > 0 {
		pub, err := ecdh.X25519().NewPublicKey(w.IdentityDHKey)
		if err != nil {
			return fmt.Errorf("x3dh: decode identity DH key: %w", err)
		}
		b.IdentityDHKey = pub
	}
	if len(w.SignedPreKey) > 0 {
		pub, err := ecdh.X25519().NewPublicKey(w.SignedPreKey)
		if err != nil {
			return fmt.Errorf("x3dh: decode signed prekey: %w", err)
		}
		b.SignedPreKey = pub
	}
	if len(w.OneTimePreKey) > 0 {
		pub, err := ecdh.X25519().NewPublicKey(w.OneTimePreKey)
		if err != nil {
			return fmt.Errorf("x3dh: decode one-time prekey: %w", err)
		}
		b.OneTimePreKey = pub
	}
	return nil
}
