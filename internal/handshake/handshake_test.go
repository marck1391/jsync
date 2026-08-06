package handshake

import (
	"crypto/rand"
	"testing"
	"time"

	"filesharer/internal/crypto/x3dh"
	"filesharer/internal/identity"
)

func newTestResponder(t *testing.T, trust *identity.Identity) (*Responder, *identity.Identity) {
	t.Helper()

	responderID, err := identity.Generate("responder-machine")
	if err != nil {
		t.Fatalf("Generate responder identity: %v", err)
	}

	authorized, err := identity.LoadAuthorizedClients(t.TempDir() + "/authorized_clients")
	if err != nil {
		t.Fatalf("LoadAuthorizedClients: %v", err)
	}
	if trust != nil {
		if err := authorized.Add(trust.PublicKey); err != nil {
			t.Fatalf("Add trusted key: %v", err)
		}
	}

	prekeys, err := x3dh.NewStore(responderID.PublicKey, responderID.PrivateKey, 5)
	if err != nil {
		t.Fatalf("x3dh.NewStore: %v", err)
	}

	r := &Responder{
		Authorized: authorized,
		Sessions:   NewSessionStore(),
		Prekeys:    prekeys,
		Guard:      NewReplayGuard(),
		DefaultParams: Params{
			MaxPayloadBytes: 1 << 20,
			AllowedDestPath: "/home/user/workspace",
		},
	}
	return r, responderID
}

func TestHandshakeHappyPath(t *testing.T) {
	initiator, err := identity.Generate("initiator-machine")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	responder, responderID := newTestResponder(t, initiator)

	req, err := BuildRequest(initiator, "/home/user/workspace/incoming", DirectionUnidirectional, false)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	resp := responder.Handle(req)
	if !resp.Approved {
		t.Fatalf("Handle: expected approval, got rejection: %s", resp.Reason)
	}
	if resp.SessionID == "" {
		t.Error("Handle: expected non-empty SessionID")
	}
	if !resp.Bundle.IdentityKey.Equal(responderID.PublicKey) {
		t.Error("Handle: Bundle.IdentityKey does not match responder's identity")
	}
	if !resp.VerifyBundle() {
		t.Error("VerifyBundle: expected the returned bundle to verify")
	}

	sess, ok := responder.Sessions.Get(resp.SessionID)
	if !ok {
		t.Fatal("Sessions.Get: session was not registered")
	}
	if sess.PeerMachineID != initiator.MachineID {
		t.Errorf("PeerMachineID = %q, want %q", sess.PeerMachineID, initiator.MachineID)
	}
	if sess.DestPath != "/home/user/workspace/incoming" {
		t.Errorf("DestPath = %q, want %q", sess.DestPath, "/home/user/workspace/incoming")
	}
	if sess.Params.Direction != DirectionUnidirectional {
		t.Errorf("Direction = %v, want DirectionUnidirectional", sess.Params.Direction)
	}
}

func TestHandshakeHonorsRequestedDirection(t *testing.T) {
	initiator, err := identity.Generate("initiator-machine")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	responder, _ := newTestResponder(t, initiator)

	req, err := BuildRequest(initiator, "/home/user/workspace/watched", DirectionBidirectional, false)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	resp := responder.Handle(req)
	if !resp.Approved {
		t.Fatalf("Handle: expected approval, got rejection: %s", resp.Reason)
	}
	if resp.Params.Direction != DirectionBidirectional {
		t.Errorf("Response Params.Direction = %v, want DirectionBidirectional", resp.Params.Direction)
	}

	sess, ok := responder.Sessions.Get(resp.SessionID)
	if !ok {
		t.Fatal("Sessions.Get: session was not registered")
	}
	if sess.Params.Direction != DirectionBidirectional {
		t.Errorf("Session Params.Direction = %v, want DirectionBidirectional", sess.Params.Direction)
	}
}

func TestHandshakeRejectsDestPathOutsideAllowedRoot(t *testing.T) {
	initiator, err := identity.Generate("initiator-machine")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	responder, _ := newTestResponder(t, initiator)

	req, err := BuildRequest(initiator, "/home/user/workspace-evil/payload", DirectionUnidirectional, false)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	resp := responder.Handle(req)
	if resp.Approved {
		t.Fatal("Handle: expected rejection for a dest path outside the allowed root")
	}
}

func TestHandshakeRejectsUnauthorizedClient(t *testing.T) {
	initiator, err := identity.Generate("initiator-machine")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	// No trust: pass nil so the initiator's key is never added.
	responder, _ := newTestResponder(t, nil)

	req, err := BuildRequest(initiator, "", DirectionUnidirectional, false)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	resp := responder.Handle(req)
	if resp.Approved {
		t.Fatal("Handle: expected rejection for unauthorized client")
	}
	if resp.Reason != ErrNotAuthorized.Error() {
		t.Errorf("Reason = %q, want %q", resp.Reason, ErrNotAuthorized.Error())
	}
}

func TestHandshakeRejectsReplay(t *testing.T) {
	initiator, err := identity.Generate("initiator-machine")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	responder, _ := newTestResponder(t, initiator)

	req, err := BuildRequest(initiator, "/home/user/workspace/incoming", DirectionUnidirectional, false)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	if resp := responder.Handle(req); !resp.Approved {
		t.Fatalf("first Handle: expected approval, got: %s", resp.Reason)
	}

	resp := responder.Handle(req)
	if resp.Approved {
		t.Fatal("second Handle with identical request: expected rejection (replay)")
	}
	if resp.Reason != ErrReplay.Error() {
		t.Errorf("Reason = %q, want %q", resp.Reason, ErrReplay.Error())
	}
}

func TestHandshakeRejectsExpiredTimestamp(t *testing.T) {
	initiator, err := identity.Generate("initiator-machine")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	responder, _ := newTestResponder(t, initiator)

	req := &Request{
		ProtocolVersion: ProtocolVersion,
		MachineID:       initiator.MachineID,
		PublicKey:       []byte(initiator.PublicKey),
		Timestamp:       time.Now().Add(-1 * time.Hour),
	}
	if _, err := rand.Read(req.Nonce[:]); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	req.Signature = initiator.Sign(req.SignedPayload())

	resp := responder.Handle(req)
	if resp.Approved {
		t.Fatal("Handle: expected rejection for stale timestamp")
	}
	if resp.Reason != ErrClockSkew.Error() {
		t.Errorf("Reason = %q, want %q", resp.Reason, ErrClockSkew.Error())
	}
}

func TestHandshakeRejectsTamperedSignature(t *testing.T) {
	initiator, err := identity.Generate("initiator-machine")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	responder, _ := newTestResponder(t, initiator)

	req, err := BuildRequest(initiator, "", DirectionUnidirectional, false)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	req.MachineID = "tampered-after-signing"

	resp := responder.Handle(req)
	if resp.Approved {
		t.Fatal("Handle: expected rejection for tampered request")
	}
}

func TestHandshakeRejectsProtocolVersionMismatch(t *testing.T) {
	initiator, err := identity.Generate("initiator-machine")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	responder, _ := newTestResponder(t, initiator)

	req, err := BuildRequest(initiator, "", DirectionUnidirectional, false)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	req.ProtocolVersion = ProtocolVersion + 1

	resp := responder.Handle(req)
	if resp.Approved {
		t.Fatal("Handle: expected rejection for protocol version mismatch")
	}
	if resp.Reason != ErrProtocolVersion.Error() {
		t.Errorf("Reason = %q, want %q", resp.Reason, ErrProtocolVersion.Error())
	}
}
