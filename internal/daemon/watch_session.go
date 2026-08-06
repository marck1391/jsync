package daemon

import (
	"context"
	"fmt"
	"os"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/handshake"
	"filesharer/internal/ignore"
	"filesharer/internal/syncfs"
	fsnats "filesharer/internal/transport/nats"
	"filesharer/internal/watch"
)

// WatchSession runs the Fase 5 receiving side for one approved bidirectional
// handshake session: creates the session's events stream and this node's
// own durable consumer on it, starts a native Watcher on sess.DestPath, and
// bridges both directions (its own local changes out, the peer's changes
// in) exactly the way cmd/fileshare's `watch` does on the initiator's side
// — the Watcher session is symmetric, neither end is privileged. Runs
// until ctx is done (the Daemon shutting down) or an unrecoverable error;
// unlike ReceiveSession there is no natural "done" point for a live sync.
func WatchSession(ctx context.Context, conn *natsgo.Conn, js jetstream.JetStream, sess *handshake.Session, localMachineID string) error {
	if err := os.MkdirAll(sess.DestPath, 0o755); err != nil {
		return fmt.Errorf("daemon: create watch root %s: %w", sess.DestPath, err)
	}

	if _, err := fsnats.EnsureEventsStream(ctx, js, sess.ID); err != nil {
		return fmt.Errorf("daemon: ensure events stream: %w", err)
	}
	cons, err := fsnats.EnsureEventsConsumer(ctx, js, sess.ID, localMachineID)
	if err != nil {
		return fmt.Errorf("daemon: ensure events consumer: %w", err)
	}

	matcher, err := ignore.Load(sess.DestPath)
	if err != nil {
		return fmt.Errorf("daemon: load %s: %w", ignore.FileName, err)
	}
	fw := watch.NewFileWatcher(watch.DefaultDebounce, watch.DefaultBufferSize, matcher)
	defer fw.Close()
	changes, watchErrs := fw.Watch(ctx, sess.DestPath)
	go func() {
		for err := range watchErrs {
			fmt.Fprintf(os.Stderr, "fileshared: watch session %s: local watch error: %v\n", sess.ID, err)
		}
	}()

	echo := syncfs.NewEchoGuard()
	versions := syncfs.NewVersionStore()
	subject := fsnats.EventsSubject(sess.ID)

	onConflict := func(ev syncfs.Event, conflictPath string) {
		fmt.Fprintf(os.Stderr, "fileshared: watch session %s: conflict on %s, wrote %s — resolve manually\n", sess.ID, ev.RelPath, conflictPath)
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- syncfs.PublishChanges(ctx, js, subject, localMachineID, sess.DestPath, changes, echo, versions)
	}()
	go func() {
		errCh <- syncfs.ReceiveChanges(ctx, cons, localMachineID, sess.DestPath, echo, versions, onConflict)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return fmt.Errorf("daemon: watch session %s ended: %w", sess.ID, err)
		}
		return nil
	}
}
