package syncfs_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/marck1391/jsync/internal/syncfs"
	fsnats "github.com/marck1391/jsync/internal/transport/nats"
)

// TestReconcileConverges drives Fase 5 §1's initial reconciliation between
// two nodes that diverged before either ever started watching: each root
// has a file unique to it, plus a file both already agree on. Reconcile
// must fill in each side's gap (union semantics) without touching the file
// they already agree on, and must do so symmetrically — both sides call
// Reconcile the same way, at the same time, exactly as cmd/jsync and
// internal/daemon.WatchSession do.
func TestReconcileConverges(t *testing.T) {
	node := bootstrapTestNode(t)
	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}

	const sessionID = "reconcile-converge"
	if _, err := fsnats.EnsureEventsStream(context.Background(), js, sessionID); err != nil {
		t.Fatalf("EnsureEventsStream: %v", err)
	}
	subject := fsnats.EventsSubject(sessionID)

	rootA := t.TempDir()
	rootB := t.TempDir()

	mustWrite(t, filepath.Join(rootA, "only-a.txt"), "from A")
	mustWrite(t, filepath.Join(rootB, "only-b.txt"), "from B")
	mustWrite(t, filepath.Join(rootA, "agreed.txt"), "already agree")
	mustWrite(t, filepath.Join(rootB, "agreed.txt"), "already agree")

	consA, err := fsnats.EnsureEventsConsumer(context.Background(), js, sessionID, "node-a")
	if err != nil {
		t.Fatalf("EnsureEventsConsumer A: %v", err)
	}
	consB, err := fsnats.EnsureEventsConsumer(context.Background(), js, sessionID, "node-b")
	if err != nil {
		t.Fatalf("EnsureEventsConsumer B: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs <- syncfs.Reconcile(ctx, js, consA, subject, "node-a", "node-b", rootA, nil, syncfs.NewVersionStore(), syncfs.NewEchoGuard(), nil, nil, nil)
	}()
	go func() {
		defer wg.Done()
		errs <- syncfs.Reconcile(ctx, js, consB, subject, "node-b", "node-a", rootB, nil, syncfs.NewVersionStore(), syncfs.NewEchoGuard(), nil, nil, nil)
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}

	mustContain(t, filepath.Join(rootB, "only-a.txt"), "from A")
	mustContain(t, filepath.Join(rootA, "only-b.txt"), "from B")
	mustContain(t, filepath.Join(rootA, "agreed.txt"), "already agree")
	mustContain(t, filepath.Join(rootB, "agreed.txt"), "already agree")
}

// TestReconcileConflict covers the case Reconcile's doc comment calls out
// explicitly: both sides have the same path with genuinely different
// content (never synced before, or diverged while apart). Reconcile must
// not silently pick a winner — both sides should end up with their own
// original content intact at the plain path, plus a *.conflict-* file
// holding the other side's version. Nothing may be lost.
func TestReconcileConflict(t *testing.T) {
	node := bootstrapTestNode(t)
	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}

	const sessionID = "reconcile-conflict"
	if _, err := fsnats.EnsureEventsStream(context.Background(), js, sessionID); err != nil {
		t.Fatalf("EnsureEventsStream: %v", err)
	}
	subject := fsnats.EventsSubject(sessionID)

	rootA := t.TempDir()
	rootB := t.TempDir()
	mustWrite(t, filepath.Join(rootA, "shared.txt"), "version A")
	mustWrite(t, filepath.Join(rootB, "shared.txt"), "version B")

	consA, err := fsnats.EnsureEventsConsumer(context.Background(), js, sessionID, "node-a")
	if err != nil {
		t.Fatalf("EnsureEventsConsumer A: %v", err)
	}
	consB, err := fsnats.EnsureEventsConsumer(context.Background(), js, sessionID, "node-b")
	if err != nil {
		t.Fatalf("EnsureEventsConsumer B: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var muA, muB sync.Mutex
	var conflictsA, conflictsB []string
	onConflictA := func(ev syncfs.Event, conflictPath string) {
		muA.Lock()
		defer muA.Unlock()
		conflictsA = append(conflictsA, conflictPath)
	}
	onConflictB := func(ev syncfs.Event, conflictPath string) {
		muB.Lock()
		defer muB.Unlock()
		conflictsB = append(conflictsB, conflictPath)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs <- syncfs.Reconcile(ctx, js, consA, subject, "node-a", "node-b", rootA, nil, syncfs.NewVersionStore(), syncfs.NewEchoGuard(), onConflictA, nil, nil)
	}()
	go func() {
		defer wg.Done()
		errs <- syncfs.Reconcile(ctx, js, consB, subject, "node-b", "node-a", rootB, nil, syncfs.NewVersionStore(), syncfs.NewEchoGuard(), onConflictB, nil, nil)
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}

	// Neither side's plain path may have been overwritten by the peer.
	mustContain(t, filepath.Join(rootA, "shared.txt"), "version A")
	mustContain(t, filepath.Join(rootB, "shared.txt"), "version B")

	muA.Lock()
	gotA := len(conflictsA)
	muA.Unlock()
	muB.Lock()
	gotB := len(conflictsB)
	muB.Unlock()
	if gotA != 1 {
		t.Fatalf("node-a got %d conflicts, want exactly 1: %v", gotA, conflictsA)
	}
	if gotB != 1 {
		t.Fatalf("node-b got %d conflicts, want exactly 1: %v", gotB, conflictsB)
	}
	mustContain(t, conflictsA[0], "version B")
	mustContain(t, conflictsB[0], "version A")
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustContain(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", path, data, want)
	}
}
