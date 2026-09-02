package nats

import (
	"encoding/json"
	"fmt"
	"time"

	natsgo "github.com/nats-io/nats.go"

	"github.com/marck1391/jsync/internal/handshake"
	"github.com/marck1391/jsync/internal/identity"
)

// ServeHandshake subscribes to this node's jsync.control.<machineID>.
// handshake subject and answers every request with r.Handle (Fase 1 §3).
// The caller (Fase 4's dispatcher) owns the returned subscription's
// lifetime.
func ServeHandshake(conn *natsgo.Conn, machineID string, r *handshake.Responder) (*natsgo.Subscription, error) {
	subject := ControlSubject(machineID, ActionHandshake)
	return conn.Subscribe(subject, func(msg *natsgo.Msg) {
		var req handshake.Request
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			// Malformed request: nothing authenticated, nothing to sign a
			// rejection with — drop it rather than reward a broken or
			// malicious sender with a reply.
			return
		}

		resp := r.Handle(&req)

		data, err := json.Marshal(resp)
		if err != nil {
			return
		}
		_ = msg.Respond(data)
	})
}

// RequestHandshake builds and signs a Fase 1 Request as id, sends it to
// targetMachineID's handshake subject, and waits up to timeout for a
// Response (Fase 1 §3 step 1: "abre un reloj de espera de 5 segundos").
// destPath is what Fase 2/5 will write to on the responder if it approves —
// pass "" for a handshake that isn't about to write anything. direction
// distinguishes a one-shot `share` from a standing `watch` session. encrypt
// requests Fase 3 end-to-end encryption for the session (share's
// --encrypt, or watch's).
func RequestHandshake(conn *natsgo.Conn, id *identity.Identity, targetMachineID, destPath string, direction handshake.Direction, encrypt bool, timeout time.Duration) (*handshake.Response, error) {
	req, err := handshake.BuildRequest(id, destPath, direction, encrypt)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("nats: encode handshake request: %w", err)
	}

	msg, err := conn.Request(ControlSubject(targetMachineID, ActionHandshake), data, timeout)
	if err != nil {
		return nil, fmt.Errorf("nats: handshake request to %s: %w", targetMachineID, err)
	}

	var resp handshake.Response
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return nil, fmt.Errorf("nats: decode handshake response: %w", err)
	}
	return &resp, nil
}
