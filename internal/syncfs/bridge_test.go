package syncfs_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/syncfs"
	fsnats "filesharer/internal/transport/nats"
	"filesharer/internal/watch"
)

func bootstrapTestNode(t *testing.T) *fsnats.Node {
	t.Helper()
	node, err := fsnats.Bootstrap(fsnats.Config{
		Role:              fsnats.RoleHub,
		Port:              0,
		LeafNodePort:      0,
		JetStreamStoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	t.Cleanup(node.Close)
	return node
}

// waitForContent polls until path contains want or the deadline passes.
func waitForContent(t *testing.T, path, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	var lastErr error
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && string(data) == want {
			return
		}
		last, lastErr = string(data), err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to contain %q; last read: %q (err: %v)", path, want, last, lastErr)
}

func waitForAbsence(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to be removed", path)
}

func TestUnidirectionalPropagation(t *testing.T) {
	node := bootstrapTestNode(t)
	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}

	const sessionID = "sync-uni"
	if _, err := fsnats.EnsureEventsStream(context.Background(), js, sessionID); err != nil {
		t.Fatalf("EnsureEventsStream: %v", err)
	}
	subject := fsnats.EventsSubject(sessionID)

	srcRoot := t.TempDir()
	destRoot := t.TempDir()

	fw := watch.NewFileWatcher(30*time.Millisecond, watch.DefaultBufferSize, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes, watchErrs := fw.Watch(ctx, srcRoot)
	defer fw.Close()
	go func() {
		for err := range watchErrs {
			t.Logf("watch error: %v", err)
		}
	}()

	srcEcho := syncfs.NewEchoGuard()
	srcVersions := syncfs.NewVersionStore()
	go func() {
		if err := syncfs.PublishChanges(ctx, js, subject, "node-src", srcRoot, changes, srcEcho, srcVersions, nil); err != nil && ctx.Err() == nil {
			t.Logf("PublishChanges: %v", err)
		}
	}()

	destCons, err := fsnats.EnsureEventsConsumer(context.Background(), js, sessionID, "node-dest")
	if err != nil {
		t.Fatalf("EnsureEventsConsumer: %v", err)
	}
	destEcho := syncfs.NewEchoGuard()
	destVersions := syncfs.NewVersionStore()
	go func() {
		if err := syncfs.ReceiveChanges(ctx, destCons, "node-dest", destRoot, destEcho, destVersions, nil, nil); err != nil && ctx.Err() == nil {
			t.Logf("ReceiveChanges: %v", err)
		}
	}()

	// Write: propagates as OpWrite.
	srcFile := filepath.Join(srcRoot, "hello.txt")
	if err := os.WriteFile(srcFile, []byte("v1"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	destFile := filepath.Join(destRoot, "hello.txt")
	waitForContent(t, destFile, "v1", 5*time.Second)

	// Modify: propagates as another OpWrite.
	if err := os.WriteFile(srcFile, []byte("v2"), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	waitForContent(t, destFile, "v2", 5*time.Second)

	// Rename: propagates as OpRename, applied as os.Rename on dest.
	renamedSrc := filepath.Join(srcRoot, "renamed.txt")
	if err := os.Rename(srcFile, renamedSrc); err != nil {
		t.Fatalf("rename: %v", err)
	}
	renamedDest := filepath.Join(destRoot, "renamed.txt")
	waitForContent(t, renamedDest, "v2", 5*time.Second)
	waitForAbsence(t, destFile, 5*time.Second)

	// Remove: propagates as OpRemove.
	if err := os.Remove(renamedSrc); err != nil {
		t.Fatalf("remove: %v", err)
	}
	waitForAbsence(t, renamedDest, 5*time.Second)
}

// TestBidirectionalNoEchoLoop is the real point of Fase 5's echo-loop
// design: two nodes both watch and both sync the same session, each
// applying the other's changes to its own directory. If the echo guard
// didn't work, node A's write would propagate to B, B's own Watcher would
// see the write it just applied and re-publish it, A would apply it again
// (a no-op content-wise, but a message nonetheless) and its Watcher — were
// Apply not carefully avoiding a local rename/rewrite signature the
// receiver's own watcher would re-trigger on — would bounce it right back,
// forever. This asserts the stream's total message count settles at
// exactly one, not climbing, after a single write.
func TestBidirectionalNoEchoLoop(t *testing.T) {
	node := bootstrapTestNode(t)
	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}

	const sessionID = "sync-bidi"
	stream, err := fsnats.EnsureEventsStream(context.Background(), js, sessionID)
	if err != nil {
		t.Fatalf("EnsureEventsStream: %v", err)
	}
	subject := fsnats.EventsSubject(sessionID)

	rootA := t.TempDir()
	rootB := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startNode := func(machineID, root string) <-chan watch.ChangeEvent {
		fw := watch.NewFileWatcher(30*time.Millisecond, watch.DefaultBufferSize, nil)
		changes, watchErrs := fw.Watch(ctx, root)
		t.Cleanup(func() { fw.Close() })
		go func() {
			for err := range watchErrs {
				t.Logf("[%s] watch error: %v", machineID, err)
			}
		}()

		echo := syncfs.NewEchoGuard()
		versions := syncfs.NewVersionStore()
		go func() {
			if err := syncfs.PublishChanges(ctx, js, subject, machineID, root, changes, echo, versions, nil); err != nil && ctx.Err() == nil {
				t.Logf("[%s] PublishChanges: %v", machineID, err)
			}
		}()

		cons, err := fsnats.EnsureEventsConsumer(context.Background(), js, sessionID, machineID)
		if err != nil {
			t.Fatalf("[%s] EnsureEventsConsumer: %v", machineID, err)
		}
		go func() {
			if err := syncfs.ReceiveChanges(ctx, cons, machineID, root, echo, versions, nil, nil); err != nil && ctx.Err() == nil {
				t.Logf("[%s] ReceiveChanges: %v", machineID, err)
			}
		}()
		return changes
	}

	startNode("node-a", rootA)
	startNode("node-b", rootB)

	fileA := filepath.Join(rootA, "shared.txt")
	if err := os.WriteFile(fileA, []byte("from A"), 0o644); err != nil {
		t.Fatalf("write on A: %v", err)
	}

	fileB := filepath.Join(rootB, "shared.txt")
	waitForContent(t, fileB, "from A", 5*time.Second)

	// Give any potential bounce a real chance to happen before checking.
	time.Sleep(1 * time.Second)

	info, err := stream.Info(context.Background())
	if err != nil {
		t.Fatalf("stream Info: %v", err)
	}
	if info.State.Msgs != 1 {
		t.Fatalf("stream has %d total messages after one write, want exactly 1 (an echo loop would keep growing this)", info.State.Msgs)
	}

	data, err := os.ReadFile(fileA)
	if err != nil {
		t.Fatalf("read fileA after settling: %v", err)
	}
	if string(data) != "from A" {
		t.Errorf("fileA content = %q, want %q (should be untouched, not bounced back and rewritten)", data, "from A")
	}
}
