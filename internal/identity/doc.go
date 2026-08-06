// Package identity owns each node's Ed25519 machine identity (Fase 1 §2):
// generating and loading the private/public identity keypair, computing the
// machine ID, and reading/writing the authorized_clients trust list
// (the authorized_keys equivalent). This is Capa 3 of the security model —
// distinct from NATS NKeys (Capa 2, transport auth) and from the X25519
// session keys in crypto/x3dh and crypto/ratchet (Capa 4, content
// confidentiality).
package identity
