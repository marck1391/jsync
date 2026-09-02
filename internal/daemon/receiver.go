package daemon

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"jsync/internal/crypto/ratchet"
	"jsync/internal/crypto/x3dh"
	"jsync/internal/handshake"
	"jsync/internal/pipeline"
	fsnats "jsync/internal/transport/nats"
)

// progressPublishInterval throttles how often ReceiveSession publishes an
// intermediate Status while a transfer is in flight — time-based, not
// per-file, so a tree of many small files doesn't flood
// jsync.status.<session_id> and a tree of a few huge files still
// reports something before the very end. A var, not a const, so a test can
// shrink it to force a deterministic progress ping instead of a real
// transfer needing to run past 500ms — same technique diskfull.go's
// isDiskFull uses for the same reason.
var progressPublishInterval = 500 * time.Millisecond

// Status is the payload published to jsync.status.<session_id> — most
// messages during a transfer are progress pings (Final: false), and
// exactly one is the terminal message (Final: true) that ends it, success
// or failure (Fase 2 §5's status channel).
type Status struct {
	SessionID string `json:"session_id"`
	Completed bool   `json:"completed"` // only meaningful when Final is true
	Error     string `json:"error,omitempty"`
	Final     bool   `json:"final"`

	// BytesReceived/TotalBytes ride both progress pings and the final
	// message. TotalBytes is EstimateSendSize's upfront (uncompressed,
	// approximate) estimate — 0 means unknown (an older sender, or the
	// estimate failed), in which case a consumer should show bytes
	// received without a percentage rather than dividing by zero.
	BytesReceived int64 `json:"bytes_received,omitempty"`
	TotalBytes    int64 `json:"total_bytes,omitempty"`
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
// (cmd/jsyncd) is what eventually deletes an abandoned sandbox no one
// ever comes back to reclaim.
//
// prekeys is this node's own X3DH material, used only if the sender turns
// out to have encrypted the transfer (chunk 0 carries an Encrypted header
// or it doesn't — see pipeline.ReceiveArchive); localIdentityPub is this
// node's Ed25519 identity key, needed to reconstruct the same Associated
// Data the sender authenticated each chunk against.
func ReceiveSession(ctx context.Context, conn *natsgo.Conn, js jetstream.JetStream, sess *handshake.Session, prekeys *x3dh.Store, localIdentityPub ed25519.PublicKey, resumes *ResumeRegistry) error {
	if _, err := fsnats.EnsureStream(ctx, js, sess.ID); err != nil {
		return publishFinalStatus(conn, sess.ID, 0, 0, fmt.Errorf("ensure stream: %w", err))
	}
	consumer, err := fsnats.EnsureStreamConsumer(ctx, js, sess.ID)
	if err != nil {
		return publishFinalStatus(conn, sess.ID, 0, 0, fmt.Errorf("ensure consumer: %w", err))
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

	// totalBytes/bytesReceived are set from two different goroutines —
	// onTotalBytes fires from ReceiveArchive's own background receive
	// loop, onFileComplete fires from this goroutine via ExtractArchive —
	// so both need real synchronization, not just "it happens to run
	// early enough in practice". lastPublishNano gates the throttle with
	// a CompareAndSwap rather than a plain check-then-set for the same
	// reason, even though in practice onFileComplete is the only one that
	// ever calls publishProgress.
	var totalBytes atomic.Int64
	var bytesReceived atomic.Int64
	var lastPublishNano atomic.Int64
	// Seeded to "now", not the zero value: an unseeded 0 would make
	// progressPublishInterval's check trivially true for the very first
	// file (any real UnixNano timestamp minus 0 is far past the
	// threshold), publishing a progress ping before a transfer has even
	// had a chance to be fast — a small/quick transfer (most tests, and
	// plenty of real ones) would then always emit an extra message before
	// the final one instead of finishing inside one throttle window.
	lastPublishNano.Store(time.Now().UnixNano())

	publishProgress := func() {
		now := time.Now().UnixNano()
		last := lastPublishNano.Load()
		if now-last < progressPublishInterval.Nanoseconds() {
			return
		}
		if !lastPublishNano.CompareAndSwap(last, now) {
			return // another goroutine just published; skip this round
		}
		st := Status{
			SessionID:     sess.ID,
			Final:         false,
			BytesReceived: bytesReceived.Load(),
			TotalBytes:    totalBytes.Load(),
		}
		_ = publish(conn, st) // progress pings are best-effort, not worth failing the transfer over
	}

	onTotalBytes := func(total int64) { totalBytes.Store(total) }
	onFileComplete := func(relPath, hash string, size int64) {
		completed[relPath] = hash
		bytesReceived.Add(size)
		publishProgress()
	}
	onSkippedSymlink := func(relPath string, cause error) {
		fmt.Fprintf(os.Stderr, "jsyncd: session %s: skipped symlink %s (unsupported on this platform): %v\n", sess.ID, relPath, cause)
	}

	pr, recvDone := pipeline.ReceiveArchive(ctx, consumer, associatedData, deriveChain, onTotalBytes)
	// If ExtractArchive below returns early on error without draining pr
	// to EOF, the goroutine behind ReceiveArchive can be left blocked
	// forever on a pipe Write with nothing left to read it — pr.Close()
	// unblocks that (a blocked/future Write on the other side of a closed
	// PipeReader returns io.ErrClosedPipe), so recvDone always receives a
	// value and that goroutine always exits.
	defer pr.Close()

	extractErr := pipeline.ExtractArchive(pr, sandboxDir, onFileComplete, onSkippedSymlink)
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
		return publishFinalStatus(conn, sess.ID, bytesReceived.Load(), totalBytes.Load(), fmt.Errorf("receive/extract: %w", cause))
	}

	if err := pipeline.CommitSandbox(sandboxDir, sess.DestPath); err != nil {
		if isDiskFull(err) {
			_ = pipeline.AbortSandbox(sandboxDir)
		} else {
			resumes.Park(sess.PeerPublicKey, sess.DestPath, sandboxDir, completed, resumeGracePeriod)
		}
		return publishFinalStatus(conn, sess.ID, bytesReceived.Load(), totalBytes.Load(), fmt.Errorf("commit: %w", err))
	}

	return publishFinalStatus(conn, sess.ID, bytesReceived.Load(), totalBytes.Load(), nil)
}

func publishFinalStatus(conn *natsgo.Conn, sessionID string, bytesReceived, totalBytes int64, cause error) error {
	st := Status{
		SessionID:     sessionID,
		Completed:     cause == nil,
		Final:         true,
		BytesReceived: bytesReceived,
		TotalBytes:    totalBytes,
	}
	if cause != nil {
		st.Error = cause.Error()
	}
	if err := publish(conn, st); err != nil {
		return err
	}
	return cause
}

func publish(conn *natsgo.Conn, st Status) error {
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("daemon: encode status: %w", err)
	}
	if pubErr := conn.Publish(fsnats.StatusSubject(st.SessionID), data); pubErr != nil {
		return fmt.Errorf("daemon: publish status: %w", pubErr)
	}
	return nil
}
