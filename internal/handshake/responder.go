package handshake

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"strings"
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

	// DefaultParams seeds new sessions with this daemon's policy (max
	// payload, allowed dest root); Handle overrides Direction from what
	// the initiator actually requested (Request.RequestedDirection) rather
	// than using DefaultParams.Direction, since that's a per-request
	// choice, not a daemon-wide one. An empty AllowedDestPath means "no
	// restriction" — an explicit operator choice to leave the destination
	// root unconstrained, not an oversight.
	DefaultParams Params

	// OnApproved, if set, is called synchronously from within Handle right
	// after a session is created — before the Response is even built. This
	// package has no knowledge of Fase 2 (internal/pipeline) or Fase 4
	// (internal/daemon) to keep the dependency direction one-way; wiring
	// "start receiving this session's stream" belongs to the caller (Fase
	// 4's daemon), not here. Handle does not wait for OnApproved to
	// return, so if it needs to do anything slower than logging, it must
	// launch its own goroutine — Handle runs inside a NATS subscription
	// callback, and blocking it here would stall every other incoming
	// handshake.
	OnApproved func(*Session)
}

// Handle validates req and returns the Response to send back over NATS. It
// never returns an error — a rejected handshake is a valid, well-formed
// Response with Approved=false, not a transport failure.
func (r *Responder) Handle(req *Request) *Response {
	if err := VerifyRequest(req, r.Authorized, r.Guard, time.Now()); err != nil {
		return &Response{Approved: false, Reason: err.Error()}
	}

	if r.DefaultParams.AllowedDestPath != "" && !pathWithinRoot(r.DefaultParams.AllowedDestPath, req.RequestedDestPath) {
		return &Response{
			Approved: false,
			Reason:   fmt.Sprintf("requested_dest_path %q is outside the allowed root %q", req.RequestedDestPath, r.DefaultParams.AllowedDestPath),
		}
	}

	params := r.DefaultParams
	params.Direction = req.RequestedDirection
	params.Encrypt = req.RequestedEncrypt

	sess, err := r.Sessions.Create(req.MachineID, ed25519.PublicKey(req.PublicKey), params, req.RequestedDestPath)
	if err != nil {
		return &Response{Approved: false, Reason: err.Error()}
	}

	if r.OnApproved != nil {
		r.OnApproved(sess)
	}

	return &Response{
		Approved:  true,
		SessionID: sess.ID,
		Params:    sess.Params,
		Bundle:    r.Prekeys.Bundle(),
	}
}

// pathWithinRoot reports whether target is root itself or nested under it,
// after cleaning both. A naive strings.HasPrefix check would let
// "/home/user/workspace-evil" pass against root "/home/user/workspace";
// this doesn't.
func pathWithinRoot(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	if root == target {
		return true
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
