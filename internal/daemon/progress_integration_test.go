package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/marck1391/jsync/internal/crypto/x3dh"
	"github.com/marck1391/jsync/internal/handshake"
	"github.com/marck1391/jsync/internal/identity"
	"github.com/marck1391/jsync/internal/pipeline"
	fsnats "github.com/marck1391/jsync/internal/transport/nats"
)

// TestReceiveSessionPublishesProgressThenFinalStatus proves ReceiveSession
// actually emits the two message shapes Status.Final distinguishes: one or
// more progress pings (Final: false) while files are still arriving, and
// exactly one terminal message (Final: true) once the transfer is fully
// committed. progressPublishInterval is shrunk to 0 for the duration of
// this test (same technique diskfull_integration_test.go uses for
// isDiskFull) so this doesn't depend on the transfer legitimately taking
// >=500ms — it forces a ping after every file instead of relying on real
// wall-clock time.
func TestReceiveSessionPublishesProgressThenFinalStatus(t *testing.T) {
	origInterval := progressPublishInterval
	progressPublishInterval = 0
	defer func() { progressPublishInterval = origInterval }()

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

	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}

	responderID, err := identity.Generate("responder")
	if err != nil {
		t.Fatalf("Generate responder: %v", err)
	}
	prekeys, err := x3dh.NewStore(responderID.PublicKey, responderID.PrivateKey, 1)
	if err != nil {
		t.Fatalf("x3dh.NewStore: %v", err)
	}
	initiatorID, err := identity.Generate("initiator")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}

	dir := t.TempDir()
	srcRoot := filepath.Join(dir, "src")
	files := map[string]string{
		"a.txt": "hello from a",
		"b.txt": "hello from b",
		"c.txt": "hello from c",
	}
	var totalSize int64
	for rel, content := range files {
		if err := os.MkdirAll(srcRoot, 0o755); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if err := os.WriteFile(filepath.Join(srcRoot, rel), []byte(content), 0o644); err != nil {
			t.Fatalf("setup write %s: %v", rel, err)
		}
		totalSize += int64(len(content))
	}
	destDir := filepath.Join(dir, "final", "dest")

	sess := &handshake.Session{ID: "sess-progress", DestPath: destDir, PeerPublicKey: initiatorID.PublicKey}
	resumes := NewResumeRegistry()

	var statuses []Status
	statusCh := make(chan Status, 32)
	sub, err := node.Conn.Subscribe(fsnats.StatusSubject(sess.ID), func(msg *natsgo.Msg) {
		var st Status
		if err := json.Unmarshal(msg.Data, &st); err == nil {
			statusCh <- st
		}
	})
	if err != nil {
		t.Fatalf("subscribe status: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sendDone := make(chan error, 1)
	go func() {
		ar := pipeline.NewArchiveReader(srcRoot, nil, nil)
		defer ar.Close()
		// Races ReceiveSession's own EnsureStream on purpose, mirroring
		// how the real Daemon and CLI run as separate processes (see
		// receiver_test.go's publishOnceStreamExists) — wait for the
		// stream to actually exist before publishing into it.
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := js.Stream(ctx, fsnats.StreamName(sess.ID)); err == nil {
				break
			}
			if time.Now().After(deadline) {
				sendDone <- context.DeadlineExceeded
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		sendDone <- pipeline.PublishArchive(ctx, js, fsnats.StreamSubject(sess.ID), ar, pipeline.DefaultChunkSize, nil, totalSize)
	}()

	if err := ReceiveSession(ctx, node.Conn, js, sess, prekeys, responderID.PublicKey, resumes); err != nil {
		t.Fatalf("ReceiveSession: %v", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("send: %v", err)
	}

	// Drain whatever arrived — give the last message(s) a moment, but
	// don't hang if fewer showed up than hoped.
	deadline := time.After(2 * time.Second)
collect:
	for {
		select {
		case st := <-statusCh:
			statuses = append(statuses, st)
			if st.Final {
				break collect
			}
		case <-deadline:
			break collect
		}
	}

	var progressCount, finalCount int
	var final Status
	for _, st := range statuses {
		if st.Final {
			finalCount++
			final = st
		} else {
			progressCount++
		}
	}

	if progressCount == 0 {
		t.Error("expected at least one progress (Final: false) Status, got none")
	}
	if finalCount != 1 {
		t.Fatalf("expected exactly one final Status, got %d (all: %+v)", finalCount, statuses)
	}
	if !final.Completed {
		t.Errorf("final status Completed = false, want true (error: %s)", final.Error)
	}
	if final.BytesReceived != totalSize {
		t.Errorf("final BytesReceived = %d, want %d", final.BytesReceived, totalSize)
	}
	if final.TotalBytes != totalSize {
		t.Errorf("final TotalBytes = %d, want %d", final.TotalBytes, totalSize)
	}
}
