package syncfs_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/syncfs"
	fsnats "filesharer/internal/transport/nats"
)

// TestConflictDetectionWritesAsideInsteadOfOverwriting drives the full
// ReceiveChanges pipeline (real NATS, real VersionStore) through a
// deliberately concurrent write: two Events for the same path, whose
// version vectors neither dominates the other, published directly
// (bypassing the live Watcher entirely so the "concurrent" ordering is
// deterministic instead of racing real filesystem timing). Fase 5 §2:
// neither write should be silently discarded — the loser of the race to
// arrive first still lands as a *.conflict-* file, never overwriting the
// winner.
func TestConflictDetectionWritesAsideInsteadOfOverwriting(t *testing.T) {
	node := bootstrapTestNode(t)
	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}

	const sessionID = "sync-conflict"
	if _, err := fsnats.EnsureEventsStream(context.Background(), js, sessionID); err != nil {
		t.Fatalf("EnsureEventsStream: %v", err)
	}
	subject := fsnats.EventsSubject(sessionID)

	destRoot := t.TempDir()
	cons, err := fsnats.EnsureEventsConsumer(context.Background(), js, sessionID, "node-observer")
	if err != nil {
		t.Fatalf("EnsureEventsConsumer: %v", err)
	}

	// Two concurrent writes to the same path from two different origins,
	// neither having seen the other's version — hand-built rather than
	// driven through a live Watcher so the race is deterministic.
	eventA := syncfs.Event{
		Origin: "node-a", Op: syncfs.OpWrite, RelPath: "shared.txt",
		ContentHash: syncfs.ContentHash([]byte("from A")), Data: []byte("from A"),
		Version: syncfs.VersionVector{"node-a": 1},
	}
	eventB := syncfs.Event{
		Origin: "node-b", Op: syncfs.OpWrite, RelPath: "shared.txt",
		ContentHash: syncfs.ContentHash([]byte("from B")), Data: []byte("from B"),
		Version: syncfs.VersionVector{"node-b": 1},
	}

	publishRaw(t, js, subject, eventA)
	publishRaw(t, js, subject, eventB)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var conflicts []string
	onConflict := func(ev syncfs.Event, conflictPath string) {
		mu.Lock()
		defer mu.Unlock()
		conflicts = append(conflicts, conflictPath)
	}

	echo := syncfs.NewEchoGuard()
	versions := syncfs.NewVersionStore()
	done := make(chan error, 1)
	go func() {
		done <- syncfs.ReceiveChanges(ctx, cons, "node-observer", destRoot, echo, versions, onConflict)
	}()

	// Wait for both the winner file and a conflict file to show up.
	deadline := time.Now().Add(5 * time.Second)
	winnerPath := filepath.Join(destRoot, "shared.txt")
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(conflicts)
		mu.Unlock()
		if _, err := os.Stat(winnerPath); err == nil && n >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(conflicts) != 1 {
		t.Fatalf("got %d conflicts, want exactly 1: %v", len(conflicts), conflicts)
	}

	winnerData, err := os.ReadFile(winnerPath)
	if err != nil {
		t.Fatalf("read winner file: %v", err)
	}
	conflictData, err := os.ReadFile(conflicts[0])
	if err != nil {
		t.Fatalf("read conflict file %s: %v", conflicts[0], err)
	}

	// Whichever event arrived first "wins" the plain path; the other must
	// land intact in the conflict file. Neither version may be lost.
	got := map[string]bool{string(winnerData): true, string(conflictData): true}
	if !got["from A"] || !got["from B"] {
		t.Fatalf("expected both \"from A\" and \"from B\" preserved somewhere; winner=%q conflict=%q", winnerData, conflictData)
	}
	if string(winnerData) == string(conflictData) {
		t.Fatalf("winner and conflict file have identical content %q — one version was lost", winnerData)
	}
}

func publishRaw(t *testing.T, js jetstream.JetStream, subject string, ev syncfs.Event) {
	t.Helper()
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if _, err := js.PublishMsg(context.Background(), &natsgo.Msg{Subject: subject, Data: data}); err != nil {
		t.Fatalf("publish event: %v", err)
	}
}
