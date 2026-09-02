package syncfs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/marck1391/jsync/internal/auditlog"
	"github.com/marck1391/jsync/internal/watch"
)

// eventFetchTimeout bounds how long ReceiveChanges blocks per Fetch call.
// Unlike Fase 2's chunkFetchTimeout, a timeout here is not an error — a
// live Watcher session can sit idle indefinitely between edits — it's just
// how often the loop wakes up to check ctx. That check matters more than it
// looks: jetstream.Consumer.Fetch takes no context of its own, so ctx
// cancellation is only ever noticed between Fetch calls, never during one
// — kept short (rather than matching chunkFetchTimeout's 30s) specifically
// so Ctrl+C on a `watch` session that's just sitting idle doesn't take up
// to 30 seconds to actually exit.
const eventFetchTimeout = 2 * time.Second

// PublishChanges drains changes (from a watch.FileWatcher on root) and
// publishes each as an Event to subject, tagged with machineID as Origin,
// until changes closes or ctx is done. Events EchoGuard recognizes as this
// node's own recent Apply (Fase 5's echo-loop guard) are dropped instead
// of published. Every OpWrite is stamped with a fresh VersionVector from
// versions (Fase 5 §2's conflict detection) — OpRemove/OpRename are not
// version-vector-tracked yet, a documented scope reduction: the write/write
// conflict (two nodes editing the same file) is the common, important
// case; remove-vs-edit conflicts need different semantics and are left for
// later.
//
// enc, if non-nil, encrypts every OpWrite's Data with enc.SendChain (Fase
// 3) before publishing — nil means the session is unencrypted, exactly as
// before Fase 3's watch support existed. The caller must have already
// completed the bootstrap dance (PublishBootstrap/ReceiveBootstrapAck or
// their responder-side mirrors) before calling this, so enc.SendChain's
// counter starts in lockstep with what the peer's enc.RecvChain expects.
// lg, if non-nil, records every published mutation (Fase 6 / auditlog) —
// nil is a valid no-op sink, same "feature off" contract as enc.
func PublishChanges(ctx context.Context, js jetstream.JetStream, subject, machineID, root string, changes <-chan watch.ChangeEvent, echo *EchoGuard, versions *VersionStore, enc *Encryption, lg *auditlog.Logger) error {
	for {
		select {
		case cev, ok := <-changes:
			if !ok {
				return nil
			}
			if err := publishOne(ctx, js, subject, machineID, root, cev, echo, versions, enc, lg); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func publishOne(ctx context.Context, js jetstream.JetStream, subject, machineID, root string, cev watch.ChangeEvent, echo *EchoGuard, versions *VersionStore, enc *Encryption, lg *auditlog.Logger) error {
	switch cev.Kind {
	case watch.ChangeRescan:
		lg.Log(auditlog.Record{
			Dir: "out", Origin: machineID, Op: "rescan", Outcome: "rescan-dropped",
			Detail: "kernel watch buffer overflowed; changes since the last event may be lost until the next reconcile",
		})
		// Reconcile (reconcile.go) now exists, but only as a one-shot run
		// before the live loop starts — re-running it mid-session from here
		// would need to pause ReceiveChanges' own Fetch on the same cons
		// (Reconcile's drain loop reads from it too) and coordinate with
		// versions/echo while they're in concurrent use, which is real
		// added complexity, not a small follow-up. Still dropped rather
		// than guessed at — see Fase 5's Notas de Implementación.
		return nil

	case watch.ChangeModified:
		data, err := os.ReadFile(cev.AbsPath)
		if err != nil {
			// Vanished between debounce firing and this read (e.g. a quick
			// create-then-delete) — the Remove that already happened, or
			// is about to, covers it; nothing to publish for a file that
			// no longer exists.
			return nil
		}
		// Hash is always computed on plaintext, encrypted or not: EchoGuard
		// and VersionStore both operate on content identity, not on
		// whatever happens to be on the wire — see Encryption's doc comment.
		hash := ContentHash(data)
		if echo.IsEcho(cev.RelPath, hash) {
			return nil
		}
		version := versions.Bump(cev.RelPath, machineID)
		plainLen := int64(len(data))
		ev := Event{Origin: machineID, Op: OpWrite, RelPath: cev.RelPath, ContentHash: hash, Data: data, Version: version}
		if enc != nil {
			ciphertext, seq, err := enc.SendChain.Encrypt(data, enc.AssociatedData)
			if err != nil {
				return fmt.Errorf("syncfs: encrypt %s: %w", cev.RelPath, err)
			}
			ev.Data = ciphertext
			ev.Seq = seq
		}
		opID, err := publishAck(ctx, js, subject, ev)
		if err != nil {
			return err
		}
		lg.Log(auditlog.Record{
			OpID: opID, Dir: "out", Origin: machineID, Op: string(OpWrite),
			RelPath: cev.RelPath, ContentHash: hash, Bytes: plainLen, Outcome: "published",
		})
		return nil

	case watch.ChangeRemoved:
		if echo.IsEchoRemove(cev.RelPath) {
			return nil
		}
		opID, err := publishAck(ctx, js, subject, Event{Origin: machineID, Op: OpRemove, RelPath: cev.RelPath})
		if err != nil {
			return err
		}
		lg.Log(auditlog.Record{
			OpID: opID, Dir: "out", Origin: machineID, Op: string(OpRemove),
			RelPath: cev.RelPath, Outcome: "published",
		})
		return nil

	case watch.ChangeRenamed:
		// Unlike OpWrite, applyRename really does call os.Rename to mirror
		// the peer's rename — so this node's own Watcher, once it starts,
		// genuinely observes a rename it didn't originate. Without this
		// check that observation would look like a brand-new local rename
		// and get re-published straight back at the peer, which no longer
		// has OldRelPath to rename from (it already renamed it away
		// itself) — the bounced event fails to apply on the peer's side
		// and aborts the whole session. See EchoGuard.MarkRenamed.
		if echo.IsEchoRename(cev.OldRelPath, cev.RelPath) {
			return nil
		}
		opID, err := publishAck(ctx, js, subject, Event{Origin: machineID, Op: OpRename, RelPath: cev.RelPath, OldRelPath: cev.OldRelPath})
		if err != nil {
			return err
		}
		lg.Log(auditlog.Record{
			OpID: opID, Dir: "out", Origin: machineID, Op: string(OpRename),
			RelPath: cev.RelPath, OldRelPath: cev.OldRelPath, Outcome: "published",
		})
		return nil
	}
	return nil
}

// applyEvent classifies and applies one already-decrypted-if-needed,
// already-Origin-filtered mutation event: OpWrite goes through
// VersionStore.Reconcile before Apply/ApplyConflict (Fase 5 §2); OpRemove
// and OpRename apply unconditionally (not version-vector-tracked yet — see
// the package doc above). Marks echo on a clean apply so this node's own
// Watcher, once it starts, recognizes the result instead of re-publishing
// it. Shared between ReceiveChanges' live loop and Reconcile's initial
// drain (reconcile.go) — the two differ only in when they stop looping and
// how they source events, not in how a single event is applied.
//
// opID is the underlying JetStream stream sequence (0 if unavailable) and
// lg, if non-nil, records the outcome — applied / conflict / stale / error
// — which is exactly the piece the events stream itself never carries.
func applyEvent(ev Event, destRoot string, echo *EchoGuard, versions *VersionStore, onConflict func(ev Event, conflictPath string), opID uint64, lg *auditlog.Logger) error {
	rec := auditlog.Record{
		OpID: opID, Dir: "in", Origin: ev.Origin, Op: string(ev.Op),
		RelPath: ev.RelPath, OldRelPath: ev.OldRelPath, ContentHash: ev.ContentHash,
	}
	if ev.Op == OpWrite {
		rec.Bytes = int64(len(ev.Data))
		safe, conflict := versions.Reconcile(ev.RelPath, ev.Version)
		if conflict {
			conflictPath, err := ApplyConflict(ev, destRoot)
			if err != nil {
				rec.Outcome, rec.Detail = "error", err.Error()
				lg.Log(rec)
				return fmt.Errorf("syncfs: write conflict file for %s: %w", ev.RelPath, err)
			}
			if onConflict != nil {
				onConflict(ev, conflictPath)
			}
			rec.Outcome, rec.ConflictPath = "conflict", conflictPath
			lg.Log(rec)
			return nil
		}
		if !safe {
			rec.Outcome = "stale" // a re-delivery, or an update already causally superseded — nothing to apply
			lg.Log(rec)
			return nil
		}
	}

	if err := Apply(ev, destRoot); err != nil {
		rec.Outcome, rec.Detail = "error", err.Error()
		lg.Log(rec)
		return fmt.Errorf("syncfs: apply %s %s: %w", ev.Op, ev.RelPath, err)
	}
	switch ev.Op {
	case OpWrite:
		echo.MarkApplied(ev.RelPath, ev.ContentHash)
	case OpRemove:
		echo.MarkRemoved(ev.RelPath)
	case OpRename:
		echo.MarkRenamed(ev.OldRelPath, ev.RelPath)
	}
	rec.Outcome = "applied"
	lg.Log(rec)
	return nil
}

// publishAck marshals and publishes ev, returning the assigned JetStream
// stream sequence — the id the audit log records so a line there points
// back at the events stream. publish is the same thing where the sequence
// isn't needed (control messages).
func publishAck(ctx context.Context, js jetstream.JetStream, subject string, ev Event) (uint64, error) {
	data, err := json.Marshal(ev)
	if err != nil {
		return 0, fmt.Errorf("syncfs: encode event: %w", err)
	}
	ack, err := js.Publish(ctx, subject, data)
	if err != nil {
		return 0, fmt.Errorf("syncfs: publish event: %w", err)
	}
	return ack.Sequence, nil
}

func publish(ctx context.Context, js jetstream.JetStream, subject string, ev Event) error {
	_, err := publishAck(ctx, js, subject, ev)
	return err
}

// ReceiveChanges pulls events from cons and applies each to destRoot,
// skipping any whose Origin is this node's own machineID — every consumer
// on the shared events stream sees every message, including the ones it
// published itself. Applied writes/removals are recorded into echo so the
// local Watcher on destRoot (if any — this node may be watching destRoot
// too, in a bidirectional sync) recognizes them instead of re-publishing.
//
// Every OpWrite is checked against versions before being applied (Fase 5
// §2). A genuine conflict — both sides wrote without having seen the
// other's change — is never silently resolved: the incoming content is
// written aside via ApplyConflict instead of overwriting the local file,
// and onConflict (if non-nil) is called so the caller can surface it (log,
// notify, etc.) — this package does no I/O beyond the filesystem itself,
// so it never prints or logs on its own.
//
// Runs until ctx is done or a Fetch/Apply error is unrecoverable; an empty
// Fetch (nothing new) is normal idle behavior, not an error.
//
// enc, if non-nil, decrypts every peer-originated OpWrite's Data with
// enc.RecvChain (Fase 3) before Reconcile/Apply ever sees it — nil means
// the session is unencrypted. The caller must have already completed the
// bootstrap dance, same requirement as PublishChanges.
//
// lg, if non-nil, records each applied mutation and its outcome (Fase 6 /
// auditlog); nil is a valid no-op sink.
func ReceiveChanges(ctx context.Context, cons jetstream.Consumer, machineID, destRoot string, echo *EchoGuard, versions *VersionStore, onConflict func(ev Event, conflictPath string), enc *Encryption, lg *auditlog.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		batch, err := cons.Fetch(1, jetstream.FetchMaxWait(eventFetchTimeout))
		if err != nil {
			return fmt.Errorf("syncfs: fetch event: %w", err)
		}

		for msg := range batch.Messages() {
			var ev Event
			if err := json.Unmarshal(msg.Data(), &ev); err != nil {
				_ = msg.Nak()
				continue // malformed event: skip it, don't kill a live session over one bad message
			}

			if ev.Origin == machineID {
				_ = msg.Ack() // our own publish, echoed back by the shared stream — nothing to apply
				continue
			}

			if ev.Op == OpBootstrap || ev.Op == OpBootstrapAck {
				// Should never reach here in a well-behaved session — both
				// are consumed by ReceiveBootstrap/ReceiveBootstrapAck
				// before this loop ever starts (encrypt.go). Ack and skip
				// rather than falling into Apply's "unknown op" error, as
				// defense in depth, not the expected path.
				_ = msg.Ack()
				continue
			}

			// Decrypted unconditionally, before applyEvent's Reconcile/
			// conflict/stale short-circuit: enc.RecvChain's counter must
			// advance exactly once for every OpWrite the peer actually
			// published, regardless of what this node then does with the
			// result. A stale/conflict message never applied is still one
			// the peer's SendChain spent a sequence number on — skipping
			// Decrypt here for such a message would desync this chain from
			// the peer's forever, breaking every OpWrite for the rest of
			// the session with an opaque GCM authentication failure.
			if enc != nil && ev.Op == OpWrite {
				plaintext, err := enc.RecvChain.Decrypt(ev.Data, enc.AssociatedData, ev.Seq)
				if err != nil {
					_ = msg.Nak()
					return fmt.Errorf("syncfs: decrypt %s: %w", ev.RelPath, err)
				}
				ev.Data = plaintext
			}

			var opID uint64
			if meta, metaErr := msg.Metadata(); metaErr == nil {
				opID = meta.Sequence.Stream
			}
			if err := applyEvent(ev, destRoot, echo, versions, onConflict, opID, lg); err != nil {
				_ = msg.Nak()
				return err
			}
			if err := msg.Ack(); err != nil {
				return fmt.Errorf("syncfs: ack event: %w", err)
			}
		}
		if batchErr := batch.Error(); batchErr != nil {
			return fmt.Errorf("syncfs: fetch event batch: %w", batchErr)
		}
	}
}
