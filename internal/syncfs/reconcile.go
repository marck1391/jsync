package syncfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/watch"
)

// ManifestEntry is one regular file's content identity for Fase 5 §1's
// initial reconciliation.
type ManifestEntry struct {
	Hash string `json:"hash"` // hex sha256
	Size int64  `json:"size"` // informational only — diffing is by Hash, not Size
}

// Manifest maps a root-relative, slash-separated path to its current
// content identity: one side's complete inventory, exchanged with the peer
// (via OpManifest) so each side can compute what the other needs without a
// round trip per file.
type Manifest map[string]ManifestEntry

// ScanManifest walks root and hashes every regular file matcher doesn't
// exclude, streaming each file through sha256 rather than buffering it
// (same posture as pipeline.NewArchiveReader). Directories and symlinks are
// skipped — a symlink has no stable content identity to diff on, and
// reconciling them would bring the same platform-support gaps already
// documented for Fase 2's transfer pipeline for comparatively little
// benefit here; a documented gap, not an oversight. matcher may be nil,
// same zero-value contract as watch.PathMatcher's other callers.
func ScanManifest(root string, matcher watch.PathMatcher) (Manifest, error) {
	m := Manifest{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if matcher != nil && matcher.Match(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil // vanished mid-walk — best-effort, same posture as watch.registerTree
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			return nil
		}
		defer f.Close()
		h := sha256.New()
		size, copyErr := io.Copy(h, f)
		if copyErr != nil {
			return nil
		}
		m[rel] = ManifestEntry{Hash: hex.EncodeToString(h.Sum(nil)), Size: size}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("syncfs: scan %s: %w", root, err)
	}
	return m, nil
}

// diffPaths returns every path in have that want doesn't already have with
// matching content — missing from want entirely, or present with a
// different hash. Exactly the set have's owner needs to push for want's
// owner to converge on those paths.
func diffPaths(have, want Manifest) []string {
	var out []string
	for path, entry := range have {
		if wantEntry, ok := want[path]; !ok || wantEntry.Hash != entry.Hash {
			out = append(out, path)
		}
	}
	return out
}

// publishManifest sends this node's complete inventory as a single
// OpManifest control message — must be the first thing either side of a
// Reconcile call publishes, mirroring PublishBootstrap's role for Fase 3.
func publishManifest(ctx context.Context, js jetstream.JetStream, subject, machineID string, m Manifest) error {
	return publish(ctx, js, subject, Event{Origin: machineID, Op: OpManifest, ReconcileManifest: m})
}

// receiveManifest blocks until peerMachineID's OpManifest arrives.
func receiveManifest(ctx context.Context, cons jetstream.Consumer, peerMachineID string) (Manifest, error) {
	ev, err := awaitControl(ctx, cons, peerMachineID, OpManifest)
	if err != nil {
		return nil, err
	}
	return ev.ReconcileManifest, nil
}

// publishReconcileDone tells the peer this node has pushed every OpWrite
// its half of the diff required — the signal Reconcile's drain loop waits
// for instead of trying to predict an exact incoming message count. A file
// that vanishes locally between being diffed and being pushed just means
// one fewer OpWrite is ever sent (see pushReconciled); the "done" control
// message still arrives and stays correct, where a fixed expected count
// would leave the peer waiting forever for a message that was never coming.
func publishReconcileDone(ctx context.Context, js jetstream.JetStream, subject, machineID string) error {
	return publish(ctx, js, subject, Event{Origin: machineID, Op: OpReconcileDone})
}

// pushReconciled reads relPath fresh — the manifest scan is a snapshot;
// content is re-read and re-hashed at send time, same "approximation, not
// guarantee" posture EstimateSendSize documents for Fase 2 — and publishes
// it as a normal OpWrite, indistinguishable on the wire from one
// PublishChanges would have produced for a live edit (VersionStore.Bump
// included, so a genuine content conflict with whatever the peer
// independently pushes for the same path is caught the same way a live
// concurrent edit would be — see Reconcile's doc comment).
func pushReconciled(ctx context.Context, js jetstream.JetStream, subject, machineID, root, relPath string, versions *VersionStore, enc *Encryption) error {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relPath)))
	if err != nil {
		return nil // vanished since the manifest scan — nothing to push
	}
	hash := ContentHash(data)
	version := versions.Bump(relPath, machineID)
	ev := Event{Origin: machineID, Op: OpWrite, RelPath: relPath, ContentHash: hash, Data: data, Version: version}
	if enc != nil {
		ciphertext, seq, encErr := enc.SendChain.Encrypt(data, enc.AssociatedData)
		if encErr != nil {
			return fmt.Errorf("encrypt %s: %w", relPath, encErr)
		}
		ev.Data = ciphertext
		ev.Seq = seq
	}
	return publish(ctx, js, subject, ev)
}

// Reconcile runs Fase 5 §1's initial reconciliation: both sides scan their
// own root, exchange manifests, and each pushes whatever the other side is
// missing or stale on — before either side's live watch.FileWatcher (and
// PublishChanges/ReceiveChanges) starts. Symmetric: both the initiator
// (cmd/fileshare) and the responder (internal/daemon.WatchSession) call
// this exact function the same way, in the same place in their startup
// sequence — right after any Fase 3 bootstrap, right before starting their
// own watch.FileWatcher — so no live change can arrive while reconciliation
// is still writing files, and nothing reconciliation writes can be
// mistaken for a live change either.
//
// Deliberately union-only, never destructive: a path present on the peer's
// side but absent locally gets filled in; the reverse never triggers a
// local delete. Telling "peer deleted it while we were apart" apart from "I
// created it after we diverged" needs more than a content diff — the same
// reason OpRemove isn't version-vector-tracked on the live path either (see
// bridge.go) — left for later, same scope reduction. A path both sides have
// with different content is a genuine conflict: both push, and
// VersionStore's normal concurrent-write detection (Fase 5 §2) takes it
// from there via applyEvent, landing the loser as a *.conflict-* file
// exactly as it would for a live concurrent edit — no
// reconciliation-specific conflict logic needed.
//
// enc, if non-nil, must already be fully established (both chains derived)
// — same requirement PublishChanges/ReceiveChanges document. onConflict, if
// non-nil, is called for every conflict Reconcile itself resolves this way.
func Reconcile(ctx context.Context, js jetstream.JetStream, cons jetstream.Consumer, subject, machineID, peerMachineID, root string, matcher watch.PathMatcher, versions *VersionStore, echo *EchoGuard, onConflict func(ev Event, conflictPath string), enc *Encryption) error {
	local, err := ScanManifest(root, matcher)
	if err != nil {
		return fmt.Errorf("syncfs: reconcile: scan local: %w", err)
	}
	if err := publishManifest(ctx, js, subject, machineID, local); err != nil {
		return fmt.Errorf("syncfs: reconcile: publish manifest: %w", err)
	}
	peer, err := receiveManifest(ctx, cons, peerMachineID)
	if err != nil {
		return fmt.Errorf("syncfs: reconcile: receive peer manifest: %w", err)
	}

	for _, relPath := range diffPaths(local, peer) {
		if err := pushReconciled(ctx, js, subject, machineID, root, relPath, versions, enc); err != nil {
			return fmt.Errorf("syncfs: reconcile: push %s: %w", relPath, err)
		}
	}
	if err := publishReconcileDone(ctx, js, subject, machineID); err != nil {
		return fmt.Errorf("syncfs: reconcile: publish done: %w", err)
	}

	return drainUntilReconcileDone(ctx, cons, machineID, peerMachineID, root, echo, versions, onConflict, enc)
}

// drainUntilReconcileDone applies every peer-originated OpWrite it sees
// (via applyEvent, the same per-message handling ReceiveChanges' live loop
// uses) until peerMachineID's OpReconcileDone arrives, then returns. This
// node's own echoed-back OpManifest/OpWrite/OpReconcileDone messages are
// skipped like any other self-origin message.
func drainUntilReconcileDone(ctx context.Context, cons jetstream.Consumer, machineID, peerMachineID, destRoot string, echo *EchoGuard, versions *VersionStore, onConflict func(Event, string), enc *Encryption) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		batch, err := cons.Fetch(1, jetstream.FetchMaxWait(eventFetchTimeout))
		if err != nil {
			return fmt.Errorf("syncfs: reconcile: fetch: %w", err)
		}

		for msg := range batch.Messages() {
			var ev Event
			if err := json.Unmarshal(msg.Data(), &ev); err != nil {
				_ = msg.Nak()
				continue // malformed message: skip it rather than abort reconciliation over one bad delivery
			}
			if ev.Origin == machineID {
				_ = msg.Ack() // our own publish, echoed back
				continue
			}
			if ev.Op == OpReconcileDone {
				_ = msg.Ack()
				return nil
			}
			if ev.Op != OpWrite {
				// Only OpWrite is expected from the peer at this point in
				// the protocol — anything else is a desync, same treatment
				// awaitControl gives an unexpected op during bootstrap.
				_ = msg.Nak()
				return fmt.Errorf("syncfs: reconcile: unexpected %s from %s", ev.Op, ev.Origin)
			}
			if enc != nil {
				plaintext, decErr := enc.RecvChain.Decrypt(ev.Data, enc.AssociatedData, ev.Seq)
				if decErr != nil {
					_ = msg.Nak()
					return fmt.Errorf("syncfs: reconcile: decrypt %s: %w", ev.RelPath, decErr)
				}
				ev.Data = plaintext
			}
			if err := applyEvent(ev, destRoot, echo, versions, onConflict); err != nil {
				_ = msg.Nak()
				return err
			}
			if err := msg.Ack(); err != nil {
				return fmt.Errorf("syncfs: reconcile: ack: %w", err)
			}
		}
		if batchErr := batch.Error(); batchErr != nil {
			return fmt.Errorf("syncfs: reconcile: fetch batch: %w", batchErr)
		}
	}
}
