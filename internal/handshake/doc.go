// Package handshake implements the Fase 1 challenge-response protocol: nonce
// + timestamp generation, Ed25519 signing/verification, protocol version
// negotiation, and the ephemeral session registry (Session ID, TTL, agreed
// parameters, and per-session NATS subject permissions). A successful
// handshake response also carries the responding node's X3DH prekey bundle
// (see crypto/x3dh) so Fase 3 can bootstrap without an extra round trip.
package handshake
