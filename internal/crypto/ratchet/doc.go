// Package ratchet implements a classical Double Ratchet chain (Fase 3):
// KDF_RK for the one DH ratchet step X3DH's SK needs to bootstrap a chain,
// and KDF_CK for per-chunk message key evolution after that. Ported by
// hand from the ftaw client/src/pq reference implementation, keeping only
// its classical path (X25519/HKDF-SHA256/AES-256-GCM) and dropping the
// ML-KEM-768 hybrid layer — see Fase 3 for the reasoning.
//
// Deliberately narrower than a general-purpose Double Ratchet: there is no
// out-of-order/skipped-message-key handling (no MAX_SKIP), and no mid-chain
// DH re-ratchet step. Both are real Double Ratchet features this package
// doesn't need yet — Fase 2's JetStream consumer already enforces strict
// in-order delivery (MaxAckPending: 1) for the one-shot, single-direction
// transfers this currently backs, so Chain.Decrypt can simply require the
// next sequence number instead of buffering skipped keys. If this package
// is ever reused for something that can legitimately deliver out of order
// (e.g. Fase 5's partitioned lanes, or long-lived bidirectional watcher
// sessions wanting periodic re-ratchet), both are additions to Chain, not
// a redesign — see Fase 3 for where periodic re-ratchet was already
// anticipated. The wire format reserves an X-PQ-KEM header for a future
// post-quantum hybrid mode without protocol breakage.
package ratchet
