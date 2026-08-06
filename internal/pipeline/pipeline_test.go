package pipeline_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/pipeline"
	fsnats "filesharer/internal/transport/nats"
)

// smallChunkSize forces several chunks even for the small test fixtures,
// so the test actually exercises chunk boundaries and the Is-Final-Chunk
// transition instead of finishing in one message.
const smallChunkSize = 16

func TestSendReceiveCommitRoundTrip(t *testing.T) {
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

	const sessionID = "test-session-roundtrip"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := fsnats.EnsureStream(ctx, js, sessionID); err != nil {
		t.Fatalf("EnsureStream: %v", err)
	}
	consumer, err := fsnats.EnsureStreamConsumer(ctx, js, sessionID)
	if err != nil {
		t.Fatalf("EnsureStreamConsumer: %v", err)
	}

	srcRoot := t.TempDir()
	writeTestSourceTree(t, srcRoot)

	subject := fsnats.StreamSubject(sessionID)

	sendErrCh := make(chan error, 1)
	go func() {
		ar := pipeline.NewArchiveReader(srcRoot)
		defer ar.Close()
		sendErrCh <- pipeline.PublishArchive(ctx, js, subject, ar, smallChunkSize)
	}()

	pr, recvDone := pipeline.ReceiveArchive(ctx, consumer)

	dir := t.TempDir()
	destDir := filepath.Join(dir, "final", "dest")
	sandboxDir := pipeline.SandboxPath(destDir, sessionID)

	if err := pipeline.ExtractArchive(pr, sandboxDir); err != nil {
		_ = pipeline.AbortSandbox(sandboxDir)
		t.Fatalf("ExtractArchive: %v", err)
	}

	if err := <-sendErrCh; err != nil {
		t.Fatalf("PublishArchive: %v", err)
	}
	if err := <-recvDone; err != nil {
		t.Fatalf("ReceiveArchive: %v", err)
	}

	if err := pipeline.CommitSandbox(sandboxDir, destDir); err != nil {
		t.Fatalf("CommitSandbox: %v", err)
	}

	for rel, want := range testSourceFiles {
		got, err := os.ReadFile(filepath.Join(destDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read committed %s: %v", rel, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
	if _, err := os.Stat(sandboxDir); !os.IsNotExist(err) {
		t.Error("sandbox should be gone after commit")
	}
}

var testSourceFiles = map[string]string{
	"root.txt":         "at the root",
	"nested/child.txt": "a bit deeper, spans multiple chunks at 16 bytes each easily",
}

func writeTestSourceTree(t *testing.T, root string) {
	t.Helper()
	for rel, content := range testSourceFiles {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("setup mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("setup write: %v", err)
		}
	}
}
