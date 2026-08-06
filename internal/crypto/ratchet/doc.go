// Package ratchet implements the classical Double Ratchet (Fase 3): KDF_RK
// and KDF_CK key derivation, per-chunk message key evolution, out-of-order
// handling up to MAX_SKIP, and periodic DH ratchet steps for long-lived
// sessions (streaming transfers, the Fase 5 watcher). Ported by hand from
// the ftaw client/src/pq reference implementation, keeping only its
// classical path (X25519/Ed25519/HKDF-SHA256/AES-256-GCM) and dropping the
// ML-KEM-768 hybrid layer — see Fase 3 for the reasoning. The wire format
// reserves an X-PQ-KEM header for a future hybrid mode without protocol
// breakage.
package ratchet
