package handshake

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/marck1391/jsync/internal/crypto/x3dh"
	"github.com/marck1391/jsync/internal/identity"
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

	// ResumeLookup, if set, is called synchronously from within Handle —
	// unlike OnApproved, its result feeds directly into the Response being
	// built, so Handle does wait for it — to fill Response.ResumedFiles for
	// a DirectionUnidirectional (share) request. Same decoupling pattern as
	// OnApproved: this package doesn't know about internal/daemon's
	// ResumeRegistry or internal/pipeline's sandboxes, just a peer identity
	// and a destination path in, a list of already-good files out. Must
	// stay fast (bounded by what a partial prior attempt already wrote, not
	// by the whole transfer) since it runs inline before the Response goes
	// out over a request-reply with its own timeout.
	ResumeLookup func(peerPub ed25519.PublicKey, destPath string) []ResumedFile
}

// Handle validates req and returns the Response to send back over NATS. It
// never returns an error — a rejected handshake is a valid, well-formed
// Response with Approved=false, not a transport failure.
func (r *Responder) Handle(req *Request) *Response {
	if err := VerifyRequest(req, r.Authorized, r.Guard, time.Now()); err != nil {
		return &Response{Approved: false, Reason: err.Error()}
	}

	if len(r.DefaultParams.AllowedDestPaths) > 0 && !anyPathWithinRoot(r.DefaultParams.AllowedDestPaths, req.RequestedDestPath) {
		return &Response{
			Approved: false,
			Reason:   fmt.Sprintf("requested_dest_path %q is outside every allowed root %v", req.RequestedDestPath, r.DefaultParams.AllowedDestPaths),
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

	var resumed []ResumedFile
	if r.ResumeLookup != nil && req.RequestedDirection == DirectionUnidirectional {
		resumed = r.ResumeLookup(ed25519.PublicKey(req.PublicKey), req.RequestedDestPath)
	}

	return &Response{
		Approved:     true,
		SessionID:    sess.ID,
		Params:       sess.Params,
		Bundle:       r.Prekeys.Bundle(),
		ResumedFiles: resumed,
	}
}

// anyPathWithinRoot reports whether target sits within at least one of
// roots — the multi-root form of the allowed-destination check.
func anyPathWithinRoot(roots []string, target string) bool {
	for _, root := range roots {
		if root != "" && pathWithinRoot(root, target) {
			return true
		}
	}
	return false
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
