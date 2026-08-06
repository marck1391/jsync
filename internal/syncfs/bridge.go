package syncfs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/watch"
)

// eventFetchTimeout bounds how long ReceiveChanges blocks per Fetch call.
// Unlike Fase 2's chunkFetchTimeout, a timeout here is not an error — a
// live Watcher session can sit idle indefinitely between edits — it's just
// how often the loop wakes up to check ctx.
const eventFetchTimeout = 30 * time.Second

// PublishChanges drains changes (from a watch.FileWatcher on root) and
// publishes each as an Event to subject, tagged with machineID as Origin,
// until changes closes or ctx is done. Events EchoGuard recognizes as this
// node's own recent Apply (Fase 5's echo-loop guard) are dropped instead
// of published.
func PublishChanges(ctx context.Context, js jetstream.JetStream, subject, machineID, root string, changes <-chan watch.ChangeEvent, echo *EchoGuard) error {
	for {
		select {
		case cev, ok := <-changes:
			if !ok {
				return nil
			}
			if err := publishOne(ctx, js, subject, machineID, root, cev, echo); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func publishOne(ctx context.Context, js jetstream.JetStream, subject, machineID, root string, cev watch.ChangeEvent, echo *EchoGuard) error {
	switch cev.Kind {
	case watch.ChangeRescan:
		// Fase 5's initial-reconciliation story isn't implemented yet (see
		// Notas de Implementación) — there's no well-defined "resync"
		// message to send for this today, so it's dropped rather than
		// guessed at.
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
		hash := ContentHash(data)
		if echo.IsEcho(cev.RelPath, hash) {
			return nil
		}
		return publish(ctx, js, subject, Event{Origin: machineID, Op: OpWrite, RelPath: cev.RelPath, ContentHash: hash, Data: data})

	case watch.ChangeRemoved:
		if echo.IsEchoRemove(cev.RelPath) {
			return nil
		}
		return publish(ctx, js, subject, Event{Origin: machineID, Op: OpRemove, RelPath: cev.RelPath})

	case watch.ChangeRenamed:
		// No echo check here by design: Apply never performs a rename
		// (see its doc comment), so a rename this node's own Watcher
		// reports can only be a genuine local rename, never a self-caused
		// echo. That's what keeps this the zero-byte-transfer path Fase 5
		// wants — no need to read and hash the file's content first.
		return publish(ctx, js, subject, Event{Origin: machineID, Op: OpRename, RelPath: cev.RelPath, OldRelPath: cev.OldRelPath})
	}
	return nil
}

func publish(ctx context.Context, js jetstream.JetStream, subject string, ev Event) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("syncfs: encode event: %w", err)
	}
	if _, err := js.Publish(ctx, subject, data); err != nil {
		return fmt.Errorf("syncfs: publish event: %w", err)
	}
	return nil
}

// ReceiveChanges pulls events from cons and applies each to destRoot,
// skipping any whose Origin is this node's own machineID — every consumer
// on the shared events stream sees every message, including the ones it
// published itself. Applied writes/removals are recorded into echo so the
// local Watcher on destRoot (if any — this node may be watching destRoot
// too, in a bidirectional sync) recognizes them instead of re-publishing.
// Runs until ctx is done or a Fetch/Apply error is unrecoverable; an empty
// Fetch (nothing new) is normal idle behavior, not an error.
func ReceiveChanges(ctx context.Context, cons jetstream.Consumer, machineID, destRoot string, echo *EchoGuard) error {
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

			if err := Apply(ev, destRoot); err != nil {
				_ = msg.Nak()
				return fmt.Errorf("syncfs: apply %s %s: %w", ev.Op, ev.RelPath, err)
			}
			switch ev.Op {
			case OpWrite:
				echo.MarkApplied(ev.RelPath, ev.ContentHash)
			case OpRemove:
				echo.MarkRemoved(ev.RelPath)
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
