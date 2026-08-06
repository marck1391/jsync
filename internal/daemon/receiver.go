package daemon

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/crypto/ratchet"
	"filesharer/internal/crypto/x3dh"
	"filesharer/internal/handshake"
	"filesharer/internal/pipeline"
	fsnats "filesharer/internal/transport/nats"
)

// Status is the payload published to fileshare.status.<session_id> once a
// Fase 2 receive finishes (Fase 2 §5's status channel — today just the one
// done/failed signal this function sends, not the per-chunk progress
// feed that section also describes; that's a documented gap, not an
// oversight, see Fase 2 for the plan).
type Status struct {
	SessionID string `json:"session_id"`
	Completed bool   `json:"completed"`
	Error     string `json:"error,omitempty"`
}

// ReceiveSession runs the Fase 2 receiving side for one approved handshake
// session (Fase 4 §Paso 1-4): creates the session's JetStream stream and
// consumer, receives (transparently decrypting, if the sender encrypted —
// Fase 3) and extracts the incoming archive into a sandbox, commits it
// atomically to sess.DestPath on success, and publishes exactly one Status
// message when done. On any failure, the sandbox is parked in resumes
// (Fase 2 "recuperación de red") instead of deleted — a later attempt from
// the same peer to the same destPath (handshake.Responder.ResumeLookup)
// can reclaim it and pick up where this one left off, skipping whatever
// files were already fully received. resumes' own watchdog sweep
// (cmd/fileshared) is what eventually deletes an abandoned sandbox no one
// ever comes back to reclaim.
//
// prekeys is this node's own X3DH material, used only if the sender turns
// out to have encrypted the transfer (chunk 0 carries an Encrypted header
// or it doesn't — see pipeline.ReceiveArchive); localIdentityPub is this
// node's Ed25519 identity key, needed to reconstruct the same Associated
// Data the sender authenticated each chunk against.
func ReceiveSession(ctx context.Context, conn *natsgo.Conn, js jetstream.JetStream, sess *handshake.Session, prekeys *x3dh.Store, localIdentityPub ed25519.PublicKey, resumes *ResumeRegistry) error {
	if _, err := fsnats.EnsureStream(ctx, js, sess.ID); err != nil {
		return publishStatus(conn, sess.ID, fmt.Errorf("ensure stream: %w", err))
	}
	consumer, err := fsnats.EnsureStreamConsumer(ctx, js, sess.ID)
	if err != nil {
		return publishStatus(conn, sess.ID, fmt.Errorf("ensure consumer: %w", err))
	}

	associatedData := x3dh.AssociatedData(sess.PeerPublicKey, localIdentityPub)
	deriveChain := pipeline.DeriveChainFunc(func(initiatorDHPub, ephemeralPub *ecdh.PublicKey, usedOTPID uint32) (*ratchet.Chain, error) {
		return prekeys.DeriveResponderChain(initiatorDHPub, ephemeralPub, usedOTPID)
	})

	sandboxDir, completed, resumed := resumes.Claim(sess.PeerPublicKey, sess.DestPath)
	if !resumed {
		sandboxDir = pipeline.SandboxPath(sess.DestPath, sess.ID)
		completed = map[string]string{}
	}
	onFileComplete := func(relPath, hash string) { completed[relPath] = hash }

	pr, recvDone := pipeline.ReceiveArchive(ctx, consumer, associatedData, deriveChain)
	// If ExtractArchive below returns early on error without draining pr
	// to EOF, the goroutine behind ReceiveArchive can be left blocked
	// forever on a pipe Write with nothing left to read it — pr.Close()
	// unblocks that (a blocked/future Write on the other side of a closed
	// PipeReader returns io.ErrClosedPipe), so recvDone always receives a
	// value and that goroutine always exits.
	defer pr.Close()

	extractErr := pipeline.ExtractArchive(pr, sandboxDir, onFileComplete)
	recvErr := <-recvDone

	if extractErr != nil || recvErr != nil {
		cause := extractErr
		if cause == nil {
			cause = recvErr
		}
		// Disk-full is the one failure this package doesn't park for
		// resume (Fase 4's original error table, and CLAUDE.md's "Siguientes
		// pasos"): retaining a half-received sandbox on an already-full
		// disk only makes the next attempt's job harder, not easier.
		if isDiskFull(cause) {
			_ = pipeline.AbortSandbox(sandboxDir)
		} else {
			resumes.Park(sess.PeerPublicKey, sess.DestPath, sandboxDir, completed, resumeGracePeriod)
		}
		return publishStatus(conn, sess.ID, fmt.Errorf("receive/extract: %w", cause))
	}

	if err := pipeline.CommitSandbox(sandboxDir, sess.DestPath); err != nil {
		if isDiskFull(err) {
			_ = pipeline.AbortSandbox(sandboxDir)
		} else {
			resumes.Park(sess.PeerPublicKey, sess.DestPath, sandboxDir, completed, resumeGracePeriod)
		}
		return publishStatus(conn, sess.ID, fmt.Errorf("commit: %w", err))
	}

	return publishStatus(conn, sess.ID, nil)
}

func publishStatus(conn *natsgo.Conn, sessionID string, cause error) error {
	st := Status{SessionID: sessionID, Completed: cause == nil}
	if cause != nil {
		st.Error = cause.Error()
	}
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("daemon: encode status: %w", err)
	}
	if pubErr := conn.Publish(fsnats.StatusSubject(sessionID), data); pubErr != nil {
		return fmt.Errorf("daemon: publish status: %w", pubErr)
	}
	return cause
}
