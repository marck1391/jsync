package nats

import (
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"

	"jsync/internal/crypto/x3dh"
	"jsync/internal/handshake"
	"jsync/internal/identity"
)

func TestServeAndRequestHandshakeOverNATS(t *testing.T) {
	hub := bootstrapHub(t)

	initiator, err := identity.Generate("initiator-machine")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	responder, err := identity.Generate("responder-machine")
	if err != nil {
		t.Fatalf("Generate responder: %v", err)
	}

	authorized, err := identity.LoadAuthorizedClients(t.TempDir() + "/authorized_clients")
	if err != nil {
		t.Fatalf("LoadAuthorizedClients: %v", err)
	}
	if err := authorized.Add(initiator.PublicKey); err != nil {
		t.Fatalf("Add: %v", err)
	}

	prekeys, err := x3dh.NewStore(responder.PublicKey, responder.PrivateKey, 3)
	if err != nil {
		t.Fatalf("x3dh.NewStore: %v", err)
	}

	r := &handshake.Responder{
		Authorized: authorized,
		Sessions:   handshake.NewSessionStore(),
		Prekeys:    prekeys,
		Guard:      handshake.NewReplayGuard(),
		DefaultParams: handshake.Params{
			MaxPayloadBytes:  1 << 20,
			AllowedDestPaths: []string{"/home/user/workspace"},
		},
	}

	// Two independent client connections to the same embedded Hub server,
	// standing in for two separate NATS-connected processes.
	initiatorConn, err := connectTo(hub)
	if err != nil {
		t.Fatalf("connect initiator: %v", err)
	}
	defer initiatorConn.Close()
	responderConn, err := connectTo(hub)
	if err != nil {
		t.Fatalf("connect responder: %v", err)
	}
	defer responderConn.Close()

	sub, err := ServeHandshake(responderConn, responder.MachineID, r)
	if err != nil {
		t.Fatalf("ServeHandshake: %v", err)
	}
	defer sub.Unsubscribe()

	resp, err := RequestHandshake(initiatorConn, initiator, responder.MachineID, "/home/user/workspace/incoming", handshake.DirectionUnidirectional, false, 2*time.Second)
	if err != nil {
		t.Fatalf("RequestHandshake: %v", err)
	}

	if !resp.Approved {
		t.Fatalf("expected approval, got rejection: %s", resp.Reason)
	}
	if resp.SessionID == "" {
		t.Error("expected non-empty SessionID")
	}
	if !resp.VerifyBundle() {
		t.Error("VerifyBundle: expected the bundle to verify after crossing the wire")
	}

	if _, ok := r.Sessions.Get(resp.SessionID); !ok {
		t.Error("responder's SessionStore does not know about the session it just approved")
	}
}

func TestRequestHandshakeRejectsUnauthorizedOverNATS(t *testing.T) {
	hub := bootstrapHub(t)

	initiator, err := identity.Generate("initiator-machine")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	responder, err := identity.Generate("responder-machine")
	if err != nil {
		t.Fatalf("Generate responder: %v", err)
	}

	// No trust configured: the responder's authorized_clients stays empty.
	authorized, err := identity.LoadAuthorizedClients(t.TempDir() + "/authorized_clients")
	if err != nil {
		t.Fatalf("LoadAuthorizedClients: %v", err)
	}
	prekeys, err := x3dh.NewStore(responder.PublicKey, responder.PrivateKey, 1)
	if err != nil {
		t.Fatalf("x3dh.NewStore: %v", err)
	}
	r := &handshake.Responder{
		Authorized: authorized,
		Sessions:   handshake.NewSessionStore(),
		Prekeys:    prekeys,
		Guard:      handshake.NewReplayGuard(),
	}

	responderConn, err := connectTo(hub)
	if err != nil {
		t.Fatalf("connect responder: %v", err)
	}
	defer responderConn.Close()
	initiatorConn, err := connectTo(hub)
	if err != nil {
		t.Fatalf("connect initiator: %v", err)
	}
	defer initiatorConn.Close()

	sub, err := ServeHandshake(responderConn, responder.MachineID, r)
	if err != nil {
		t.Fatalf("ServeHandshake: %v", err)
	}
	defer sub.Unsubscribe()

	resp, err := RequestHandshake(initiatorConn, initiator, responder.MachineID, "", handshake.DirectionUnidirectional, false, 2*time.Second)
	if err != nil {
		t.Fatalf("RequestHandshake: %v", err)
	}
	if resp.Approved {
		t.Fatal("expected rejection for an unauthorized initiator")
	}
}

func connectTo(n *Node) (*natsgo.Conn, error) {
	return natsgo.Connect(n.ClientURL())
}
