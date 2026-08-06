package handshake

import (
	"crypto/ed25519"
	"time"

	"filesharer/internal/crypto/x3dh"
	"filesharer/internal/identity"
)

// Responder runs the full Fase 1 §3 flow on the receiving side: validate,
// look up authorization, mint a session, and attach a fresh prekey bundle.
// It has no NATS knowledge — internal/transport/nats wires the subject and
// Fase 4's dispatcher calls Handle per incoming request.
type Responder struct {
	Authorized *identity.AuthorizedClients
	Sessions   *SessionStore
	Prekeys    *x3dh.Store
	Guard      *ReplayGuard

	// DefaultParams seeds new sessions; real values come from Fase 4's
	// config (max payload, allowed dest root, watcher vs. one-shot, etc.).
	DefaultParams Params
}

// Handle validates req and returns the Response to send back over NATS. It
// never returns an error — a rejected handshake is a valid, well-formed
// Response with Approved=false, not a transport failure.
func (r *Responder) Handle(req *Request) *Response {
	if err := VerifyRequest(req, r.Authorized, r.Guard, time.Now()); err != nil {
		return &Response{Approved: false, Reason: err.Error()}
	}

	sess, err := r.Sessions.Create(req.MachineID, ed25519.PublicKey(req.PublicKey), r.DefaultParams)
	if err != nil {
		return &Response{Approved: false, Reason: err.Error()}
	}

	return &Response{
		Approved:  true,
		SessionID: sess.ID,
		Params:    sess.Params,
		Bundle:    r.Prekeys.Bundle(),
	}
}
