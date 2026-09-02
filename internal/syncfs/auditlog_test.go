package syncfs_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"jsync/internal/auditlog"
	"jsync/internal/syncfs"
	fsnats "jsync/internal/transport/nats"
	"jsync/internal/watch"
)

// TestAuditLogRecordsPropagation drives one real write through
// PublishChanges -> NATS -> ReceiveChanges with a live auditlog.Logger on
// each side, and asserts the publisher logged a "published" out-record and
// the receiver an "applied" in-record for the same path, both carrying the
// JetStream stream sequence as OpID.
func TestAuditLogRecordsPropagation(t *testing.T) {
	node := bootstrapTestNode(t)
	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}

	const sessionID = "sync-audit"
	if _, err := fsnats.EnsureEventsStream(context.Background(), js, sessionID); err != nil {
		t.Fatalf("EnsureEventsStream: %v", err)
	}
	subject := fsnats.EventsSubject(sessionID)

	srcRoot := t.TempDir()
	destRoot := t.TempDir()
	srcLogDir := t.TempDir()
	destLogDir := t.TempDir()

	srcLog, err := auditlog.Open(srcLogDir, srcRoot, sessionID)
	if err != nil {
		t.Fatalf("open src audit log: %v", err)
	}
	defer srcLog.Close()
	destLog, err := auditlog.Open(destLogDir, destRoot, sessionID)
	if err != nil {
		t.Fatalf("open dest audit log: %v", err)
	}
	defer destLog.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fw := watch.NewFileWatcher(30*time.Millisecond, watch.DefaultBufferSize, nil)
	changes, watchErrs := fw.Watch(ctx, srcRoot)
	defer fw.Close()
	go func() {
		for range watchErrs {
		}
	}()

	srcEcho := syncfs.NewEchoGuard()
	srcVersions := syncfs.NewVersionStore()
	go func() {
		if err := syncfs.PublishChanges(ctx, js, subject, "node-src", srcRoot, changes, srcEcho, srcVersions, nil, srcLog); err != nil && ctx.Err() == nil {
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
		if err := syncfs.ReceiveChanges(ctx, destCons, "node-dest", destRoot, destEcho, destVersions, nil, nil, destLog); err != nil && ctx.Err() == nil {
			t.Logf("ReceiveChanges: %v", err)
		}
	}()

	if err := os.WriteFile(filepath.Join(srcRoot, "hello.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitForContent(t, filepath.Join(destRoot, "hello.txt"), "v1", 5*time.Second)

	// Give both loggers a moment to flush their line after the file lands.
	out := waitForRecord(t, srcLogDir, srcRoot, func(r auditlog.Record) bool {
		return r.Dir == "out" && r.Op == "write" && r.RelPath == "hello.txt" && r.Outcome == "published"
	})
	in := waitForRecord(t, destLogDir, destRoot, func(r auditlog.Record) bool {
		return r.Dir == "in" && r.Op == "write" && r.RelPath == "hello.txt" && r.Outcome == "applied"
	})

	if out.OpID == 0 || in.OpID == 0 {
		t.Errorf("expected non-zero OpID on both sides, got out=%d in=%d", out.OpID, in.OpID)
	}
	if out.OpID != in.OpID {
		t.Errorf("publisher and receiver logged different OpIDs for the same event: out=%d in=%d", out.OpID, in.OpID)
	}
	if out.Bytes != 2 || in.Bytes != 2 {
		t.Errorf("expected Bytes=2 (len \"v1\") on both sides, got out=%d in=%d", out.Bytes, in.Bytes)
	}
	if out.ContentHash == "" || out.ContentHash != in.ContentHash {
		t.Errorf("content hash mismatch or empty: out=%q in=%q", out.ContentHash, in.ContentHash)
	}
}

func waitForRecord(t *testing.T, dir, root string, pred func(auditlog.Record) bool) auditlog.Record {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		recs, err := auditlog.List(dir, auditlog.Query{Root: root})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		for _, r := range recs {
			if pred(r) {
				return r
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for a matching audit record under %s", dir)
	return auditlog.Record{}
}
