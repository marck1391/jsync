// Package x3dh implements X3DH (Extended Triple Diffie-Hellman) session
// establishment (Fase 3): prekey bundle generation on the responding side
// (Identity Key, Signed PreKey + signature, One-Time PreKeys), rotation of
// that material, and the initiator-side derivation of the shared secret SK
// from a received bundle. SK only ever seeds crypto/ratchet — it is never
// used to encrypt bytes directly. Deliberately classical only: X25519 +
// Ed25519 + HKDF-SHA256, no post-quantum KEM (see Fase 3 for why).
package x3dh
