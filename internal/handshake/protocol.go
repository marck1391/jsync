package handshake

import (
	"encoding/binary"
	"time"

	"filesharer/internal/crypto/x3dh"
)

// ProtocolVersion is checked first in a handshake (Fase 1 §3 step 1) so an
// incompatible pair of nodes fails fast, before spending any cycles on
// cryptography.
const ProtocolVersion = 1

// Request is the challenge sent by the initiating node to
// fileshare.control.<target_machine_id>.handshake (Fase 1 §3 step 1).
type Request struct {
	ProtocolVersion int
	MachineID       string
	PublicKey       []byte // Ed25519, 32 bytes
	Timestamp       time.Time
	Nonce           [16]byte
	Signature       []byte // over SignedPayload()
}

// SignedPayload returns the exact bytes the requester signs and the
// responder re-derives to verify. Beyond the Timestamp + Nonce called out
// in Fase 1 §3 step 1, it also binds MachineID (length-prefixed, since it's
// variable-length) and PublicKey into the signature: leaving MachineID out
// would let a relay rewrite it in transit without invalidating the
// signature, since it's the only field here not otherwise bound to the
// verification key.
func (r *Request) SignedPayload() []byte {
	buf := make([]byte, 0, 4+8+len(r.Nonce)+4+len(r.MachineID)+len(r.PublicKey))
	buf = binary.BigEndian.AppendUint32(buf, uint32(r.ProtocolVersion))
	buf = binary.BigEndian.AppendUint64(buf, uint64(r.Timestamp.UnixNano()))
	buf = append(buf, r.Nonce[:]...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(r.MachineID)))
	buf = append(buf, r.MachineID...)
	buf = append(buf, r.PublicKey...)
	return buf
}

// Direction records whether a session is a one-shot unidirectional transfer
// (Fase 2) or a bidirectional watcher session (Fase 5) — it drives which
// NATS subject permissions get granted for the session (Capa 2).
type Direction int

const (
	DirectionUnidirectional Direction = iota
	DirectionBidirectional
)

// Params are the agreed-upon session parameters the responder hands back
// (Fase 1 §3 step 3): constraints the initiator must respect.
type Params struct {
	MaxPayloadBytes int64
	AllowedDestPath string
	Direction       Direction
}

// Response is what the responding node sends back, approved or not (Fase 1
// §3 step 4).
type Response struct {
	Approved  bool
	Reason    string // set when Approved is false
	SessionID string
	Params    Params
	Bundle    x3dh.Bundle
}

// VerifyBundle checks that Bundle's Signed PreKey was actually signed by
// Bundle's Identity Key, before the initiator trusts it to bootstrap X3DH
// (Fase 3 §1: "evita que un Prekey Bundle falso se cuele"). Returns false
// for an unapproved response.
func (resp *Response) VerifyBundle() bool {
	if !resp.Approved || resp.Bundle.SignedPreKey == nil {
		return false
	}
	return x3dh.VerifySignedPreKey(resp.Bundle.IdentityKey, resp.Bundle.SignedPreKey, resp.Bundle.SignedPreKeySignature)
}
