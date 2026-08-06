package syncfs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Op is the mutation kind a syncfs Event carries (Fase 5 §"Protocolo de
// Mensajes de Evento").
type Op string

const (
	OpWrite  Op = "write" // covers both CREATE and WRITE — the receiving side treats them identically (see Apply)
	OpRemove Op = "remove"
	OpRename Op = "rename"

	// OpBootstrap and OpBootstrapAck are control messages, not filesystem
	// mutations — Apply never sees them. They carry Fase 3's X3DH bootstrap
	// material over the events subject (mirroring Fase 2's chunk-0
	// Bootstrap-* headers, generalized to a stream with no fixed "chunk
	// 0") so both sides of a Fase 5 Watcher session can derive matching
	// Double Ratchet chains before any real Event needs encrypting or
	// decrypting. See encrypt.go.
	OpBootstrap    Op = "bootstrap"
	OpBootstrapAck Op = "bootstrap_ack"
)

// Event is one filesystem mutation propagated between two Watcher sessions
// (Fase 5). ContentHash and Data are only set for OpWrite.
type Event struct {
	// Origin is the publishing node's machine_id — lets a consumer
	// recognize its own publish echoed back by the shared events stream
	// (every consumer on that stream sees every message, including the
	// one it published itself) and skip re-applying it.
	Origin string `json:"origin"`

	Op         Op     `json:"op"`
	RelPath    string `json:"rel_path"`
	OldRelPath string `json:"old_rel_path,omitempty"` // only for OpRename

	ContentHash string `json:"content_hash,omitempty"` // hex sha256, only for OpWrite
	Data        []byte `json:"data,omitempty"`         // only for OpWrite; large-file redirect to Fase 2 streaming is a documented follow-up, not implemented yet

	// Version is RelPath's causal version vector as of this write, used to
	// tell a genuine update from a genuine conflict (Fase 5 §2 / version.go).
	// Only set for OpWrite — see bridge.go for why OpRemove/OpRename aren't
	// version-vector-tracked yet.
	Version VersionVector `json:"version,omitempty"`

	// Seq is the Double Ratchet chain sequence number Data was encrypted
	// under (encrypt.go) — set only for an encrypted OpWrite, the same role
	// Fase 2's Chunk-Sequence header plays for pipeline.ReceiveArchive: it
	// lets Decrypt report a clear "out of order" error instead of a bare
	// GCM authentication failure if a chain ever desyncs.
	Seq uint32 `json:"seq,omitempty"`

	// Bootstrap* fields only ride OpBootstrap/OpBootstrapAck (encrypt.go);
	// every other Op leaves them empty. Raw bytes rather than *ecdh.PublicKey
	// so this package's wire type stays free of crypto-library types, the
	// same split Fase 2's pipeline package keeps between its own headers
	// and x3dh.Store.
	BootstrapInitiatorDHPub []byte `json:"bootstrap_initiator_dh_pub,omitempty"` // OpBootstrap only
	BootstrapEphemeralPub   []byte `json:"bootstrap_ephemeral_pub,omitempty"`    // OpBootstrap and OpBootstrapAck
	BootstrapUsedOTPID      uint32 `json:"bootstrap_used_otp_id,omitempty"`      // OpBootstrap only
}

// ContentHash returns the hex-encoded SHA-256 of data — the currency
// EchoGuard trades in, and what a receiver could (future work) use to
// detect a genuine conflict versus a redundant re-send of identical
// content.
func ContentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Apply mirrors ev onto destRoot (Fase 5 §"Flujo de Reproducción en el
// Daemon"). OpWrite writes directly to the target path (O_CREATE|O_TRUNC),
// deliberately not via a temp-file-then-rename: Apply must never itself
// trigger a rename on the local filesystem, because publishOne (event.go)
// treats every observed ChangeRenamed as genuine and always propagates it
// — if Apply used temp+rename to "commit" a write, its own local Watcher
// would see that rename and re-publish it, breaking the echo-loop guard
// this whole package exists to provide. The atomicity this trades away
// (a reader could observe a partially-written file mid-Apply) is a
// documented gap, not an oversight — see Fase 5's Notas de Implementación.
func Apply(ev Event, destRoot string) error {
	switch ev.Op {
	case OpWrite:
		return applyWrite(ev, destRoot)
	case OpRemove:
		return applyRemove(ev, destRoot)
	case OpRename:
		return applyRename(ev, destRoot)
	default:
		return fmt.Errorf("syncfs: unknown op %q", ev.Op)
	}
}

// ApplyConflict writes ev's content aside instead of overwriting RelPath —
// called instead of Apply when VersionStore.Reconcile reports a genuine
// conflict (Fase 5 §2: notification style, no silent auto-merge). Returns
// the path it wrote to, so the caller can log/report it. The conflict file
// lands as a plain new file under destRoot, which means this node's own
// Watcher will pick it up and propagate it like any other write — the
// other side ends up seeing the same conflict marker too, without any
// special-casing needed here.
func ApplyConflict(ev Event, destRoot string) (string, error) {
	target, err := safePath(destRoot, ev.RelPath)
	if err != nil {
		return "", err
	}
	conflictPath := fmt.Sprintf("%s.conflict-%s-%d", target, sanitizeForFilename(ev.Origin), time.Now().Unix())
	if err := os.MkdirAll(filepath.Dir(conflictPath), 0o755); err != nil {
		return "", fmt.Errorf("syncfs: mkdir %s: %w", filepath.Dir(conflictPath), err)
	}
	if err := os.WriteFile(conflictPath, ev.Data, 0o644); err != nil {
		return "", fmt.Errorf("syncfs: write conflict file %s: %w", conflictPath, err)
	}
	return conflictPath, nil
}

// sanitizeForFilename replaces path separators in a machine_id (which
// could in principle contain them — see transport/nats.sanitizeConsumerName
// for the same concern) so it can't turn a conflict filename into a path
// escape.
func sanitizeForFilename(s string) string {
	return strings.NewReplacer("/", "_", "\\", "_").Replace(s)
}

func applyWrite(ev Event, destRoot string) error {
	target, err := safePath(destRoot, ev.RelPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("syncfs: mkdir %s: %w", filepath.Dir(target), err)
	}
	if err := os.WriteFile(target, ev.Data, 0o644); err != nil {
		return fmt.Errorf("syncfs: write %s: %w", target, err)
	}
	return nil
}

func applyRemove(ev Event, destRoot string) error {
	target, err := safePath(destRoot, ev.RelPath)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("syncfs: remove %s: %w", target, err)
	}
	return nil
}

func applyRename(ev Event, destRoot string) error {
	oldTarget, err := safePath(destRoot, ev.OldRelPath)
	if err != nil {
		return err
	}
	newTarget, err := safePath(destRoot, ev.RelPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(newTarget), 0o755); err != nil {
		return fmt.Errorf("syncfs: mkdir %s: %w", filepath.Dir(newTarget), err)
	}
	if err := os.Rename(oldTarget, newTarget); err != nil {
		return fmt.Errorf("syncfs: rename %s -> %s: %w", oldTarget, newTarget, err)
	}
	return nil
}

// safePath joins root and relPath, rejecting a result that would escape
// root (e.g. relPath == "../../etc/passwd") — a hostile or buggy peer must
// not be able to write outside the synced directory.
func safePath(root, relPath string) (string, error) {
	target := filepath.Join(root, filepath.FromSlash(relPath))
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("syncfs: path %q escapes root", relPath)
	}
	return target, nil
}
