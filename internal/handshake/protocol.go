package handshake

import (
	"encoding/binary"
	"time"

	"jsync/internal/crypto/x3dh"
)

// ProtocolVersion is checked first in a handshake (Fase 1 §3 step 1) so an
// incompatible pair of nodes fails fast, before spending any cycles on
// cryptography.
const ProtocolVersion = 2

// Request is the challenge sent by the initiating node to
// jsync.control.<target_machine_id>.handshake (Fase 1 §3 step 1).
type Request struct {
	ProtocolVersion int       `json:"protocol_version"`
	MachineID       string    `json:"machine_id"`
	PublicKey       []byte    `json:"public_key"` // Ed25519, 32 bytes
	Timestamp       time.Time `json:"timestamp"`
	Nonce           [16]byte  `json:"nonce"`

	// RequestedDestPath is where the initiator wants Fase 2 to write on
	// the responder's filesystem. Deciding this at handshake time (Fase 1
	// §3 step 3: "rutas permitidas de destino") lets the Responder reject
	// an out-of-policy path before any bytes move, and lets Session carry
	// the already-validated path forward to Fase 2 without re-parsing it
	// out of stream metadata.
	RequestedDestPath string `json:"requested_dest_path"`

	// RequestedDirection tells the responder whether this is a one-shot
	// `share` (Fase 2) or a live `watch` session (Fase 5) — the responder
	// copies it into the approved Session's Params.Direction, and
	// Fase 4's OnApproved branches on that to start either a Fase 2
	// receive or a Fase 5 watcher on RequestedDestPath.
	RequestedDirection Direction `json:"requested_direction"`

	// RequestedEncrypt tells the responder whether this session should run
	// its payload through Fase 3's X3DH + Double Ratchet (share's
	// --encrypt, or watch's — see internal/daemon.WatchSession and
	// internal/syncfs's bootstrap dance). Signed for the same reason
	// RequestedDestPath and RequestedDirection are: without it, a relay
	// could silently strip an encryption request and downgrade the session
	// to plaintext without either side noticing.
	RequestedEncrypt bool `json:"requested_encrypt"`

	Signature []byte `json:"signature"` // over SignedPayload()
}

// SignedPayload returns the exact bytes the requester signs and the
// responder re-derives to verify. Beyond the Timestamp + Nonce called out
// in Fase 1 §3 step 1, it also binds MachineID, RequestedDestPath,
// RequestedDirection, and RequestedEncrypt (length-prefixed where
// variable-length) and PublicKey into the signature: leaving any of those
// out would let a relay rewrite them in transit without invalidating the
// signature, since they're the only fields here not otherwise bound to the
// verification key. RequestedDestPath in particular matters — an unsigned
// destination path is a relay's invitation to redirect where an approved
// transfer writes on disk. RequestedDirection matters too, if quieter: it
// decides whether the responder starts a one-shot receive or a standing
// Watcher on that path. RequestedEncrypt matters for the same reason: an
// unsigned encrypt flag is a relay's invitation to downgrade an encrypted
// session to plaintext.
func (r *Request) SignedPayload() []byte {
	buf := make([]byte, 0, 4+8+len(r.Nonce)+4+len(r.MachineID)+4+len(r.RequestedDestPath)+4+1+len(r.PublicKey))
	buf = binary.BigEndian.AppendUint32(buf, uint32(r.ProtocolVersion))
	buf = binary.BigEndian.AppendUint64(buf, uint64(r.Timestamp.UnixNano()))
	buf = append(buf, r.Nonce[:]...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(r.MachineID)))
	buf = append(buf, r.MachineID...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(r.RequestedDestPath)))
	buf = append(buf, r.RequestedDestPath...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(r.RequestedDirection))
	if r.RequestedEncrypt {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = append(buf, r.PublicKey...)
	return buf
}

// Direction records whether a session is a one-shot unidirectional transfer
// (Fase 2) or a bidirectional watcher session (Fase 5) — it drives which
// NATS subject permissions get granted for the session (Capa 2), and which
// of Fase 4's OnApproved branches runs.
type Direction int

const (
	DirectionUnidirectional Direction = iota
	DirectionBidirectional
)

// Params are the agreed-upon session parameters the responder hands back
// (Fase 1 §3 step 3): constraints the initiator must respect.
type Params struct {
	MaxPayloadBytes  int64     `json:"max_payload_bytes"`
	AllowedDestPaths []string  `json:"allowed_dest_paths,omitempty"`
	Direction        Direction `json:"direction"`
	// Encrypt mirrors Request.RequestedEncrypt (Responder.Handle copies it
	// straight through, same as Direction) — internal/daemon.WatchSession
	// reads this to decide whether to run the Fase 3 bootstrap dance before
	// starting its Watcher.
	Encrypt bool `json:"encrypt"`
}

// Response is what the responding node sends back, approved or not (Fase 1
// §3 step 4).
type Response struct {
	Approved  bool        `json:"approved"`
	Reason    string      `json:"reason,omitempty"` // set when Approved is false
	SessionID string      `json:"session_id,omitempty"`
	Params    Params      `json:"params"`
	Bundle    x3dh.Bundle `json:"bundle"`

	// ResumedFiles lists files the responder already has a verified-good
	// copy of for this exact (requester, RequestedDestPath) pair, left over
	// from a previous attempt that didn't finish (network recovery for
	// `share` — see Responder.ResumeLookup). The initiator can skip
	// re-archiving any of these whose local content still hashes to the
	// same digest. Empty for a `watch` session, or a `share` with nothing
	// to resume.
	ResumedFiles []ResumedFile `json:"resumed_files,omitempty"`
}

// ResumedFile is one file the responder already has fully and correctly
// from an interrupted prior attempt — see Response.ResumedFiles.
type ResumedFile struct {
	RelPath     string `json:"rel_path"`
	ContentHash string `json:"content_hash"` // hex sha256
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
