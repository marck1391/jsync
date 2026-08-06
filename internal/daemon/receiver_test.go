package daemon_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/crypto/x3dh"
	"filesharer/internal/daemon"
	"filesharer/internal/handshake"
	"filesharer/internal/identity"
	"filesharer/internal/pipeline"
	fsnats "filesharer/internal/transport/nats"
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

func newResponderPrekeys(t *testing.T) (*x3dh.Store, *identity.Identity) {
	t.Helper()
	id, err := identity.Generate("responder")
	if err != nil {
		t.Fatalf("Generate responder identity: %v", err)
	}
	store, err := x3dh.NewStore(id.PublicKey, id.PrivateKey, 1)
	if err != nil {
		t.Fatalf("x3dh.NewStore: %v", err)
	}
	return store, id
}

func TestReceiveSessionSuccess(t *testing.T) {
	node := bootstrapTestNode(t)
	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}
	prekeys, responderID := newResponderPrekeys(t)
	initiatorID, err := identity.Generate("initiator")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}

	dir := t.TempDir()
	srcRoot := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcRoot, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "hello.txt"), []byte("hello from the sender"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	destDir := filepath.Join(dir, "final", "dest")
	sess := &handshake.Session{ID: "sess-success", DestPath: destDir, PeerPublicKey: initiatorID.PublicKey}

	statusCh := subscribeStatus(t, node.Conn, sess.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sendDone := make(chan error, 1)
	go func() {
		ar := pipeline.NewArchiveReader(srcRoot)
		defer ar.Close()
		sendDone <- publishOnceStreamExists(ctx, js, sess.ID, ar, nil)
	}()

	if err := daemon.ReceiveSession(ctx, node.Conn, js, sess, prekeys, responderID.PublicKey); err != nil {
		t.Fatalf("ReceiveSession: %v", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("send: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(destDir, "hello.txt"))
	if err != nil {
		t.Fatalf("read committed file: %v", err)
	}
	if string(data) != "hello from the sender" {
		t.Errorf("content = %q, want %q", data, "hello from the sender")
	}

	st := waitStatus(t, statusCh)
	if !st.Completed {
		t.Errorf("status.Completed = false, want true (error: %s)", st.Error)
	}
}

// TestReceiveSessionEncryptedSuccess mirrors TestReceiveSessionSuccess but
// drives the sender side the way cmd/fileshare's --encrypt actually does:
// real X3DH against the responder's Bundle, a real Double Ratchet chain,
// chunk 0 carrying the bootstrap headers. Proves daemon.ReceiveSession
// derives a matching chain purely from what's on the wire and decrypts
// correctly, not just that internal/pipeline can in isolation.
func TestReceiveSessionEncryptedSuccess(t *testing.T) {
	node := bootstrapTestNode(t)
	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}
	prekeys, responderID := newResponderPrekeys(t)
	initiatorID, err := identity.Generate("initiator")
	if err != nil {
		t.Fatalf("Generate initiator: %v", err)
	}
	initiatorStore, err := x3dh.NewStore(initiatorID.PublicKey, initiatorID.PrivateKey, 0)
	if err != nil {
		t.Fatalf("initiator x3dh.NewStore: %v", err)
	}

	dir := t.TempDir()
	srcRoot := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcRoot, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "secret.txt"), []byte("only the responder should ever decrypt this"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	destDir := filepath.Join(dir, "final", "dest")
	sess := &handshake.Session{ID: "sess-encrypted", DestPath: destDir, PeerPublicKey: initiatorID.PublicKey}
	statusCh := subscribeStatus(t, node.Conn, sess.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// This is exactly what the handshake response would have carried.
	bundle := prekeys.Bundle()
	chain, ephemeralPub, usedOTPID, err := initiatorStore.DeriveInitiatorChain(bundle)
	if err != nil {
		t.Fatalf("DeriveInitiatorChain: %v", err)
	}
	enc := &pipeline.Encryption{
		Chain:          chain,
		AssociatedData: x3dh.AssociatedData(initiatorID.PublicKey, responderID.PublicKey),
		Bootstrap: pipeline.EncryptionBootstrap{
			InitiatorDHPub: initiatorStore.IdentityDHPublicKey(),
			EphemeralPub:   ephemeralPub,
			UsedOTPID:      usedOTPID,
		},
	}

	sendDone := make(chan error, 1)
	go func() {
		ar := pipeline.NewArchiveReader(srcRoot)
		defer ar.Close()
		sendDone <- publishOnceStreamExists(ctx, js, sess.ID, ar, enc)
	}()

	if err := daemon.ReceiveSession(ctx, node.Conn, js, sess, prekeys, responderID.PublicKey); err != nil {
		t.Fatalf("ReceiveSession: %v", err)
	}
	if err := <-sendDone; err != nil {
		t.Fatalf("send: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(destDir, "secret.txt"))
	if err != nil {
		t.Fatalf("read committed file: %v", err)
	}
	if string(data) != "only the responder should ever decrypt this" {
		t.Errorf("content = %q, want the original plaintext", data)
	}

	st := waitStatus(t, statusCh)
	if !st.Completed {
		t.Errorf("status.Completed = false, want true (error: %s)", st.Error)
	}
}

func TestReceiveSessionCorruptStreamFailsAndCleansUp(t *testing.T) {
	node := bootstrapTestNode(t)
	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}
	prekeys, responderID := newResponderPrekeys(t)

	dir := t.TempDir()
	destDir := filepath.Join(dir, "final", "dest")
	sess := &handshake.Session{ID: "sess-corrupt", DestPath: destDir}

	statusCh := subscribeStatus(t, node.Conn, sess.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := fsnats.EnsureStream(ctx, js, sess.ID); err != nil {
		t.Fatalf("EnsureStream: %v", err)
	}
	// Publish garbage that isn't a valid gzip stream, marked final
	// immediately, so ReceiveSession's extraction step fails.
	msg := &natsgo.Msg{Subject: fsnats.StreamSubject(sess.ID), Data: []byte("not gzip data")}
	msg.Header = natsgo.Header{}
	msg.Header.Set(pipeline.HeaderChunkSequence, "0")
	msg.Header.Set(pipeline.HeaderIsFinalChunk, "true")
	if _, err := js.PublishMsg(ctx, msg); err != nil {
		t.Fatalf("publish corrupt chunk: %v", err)
	}

	if err := daemon.ReceiveSession(ctx, node.Conn, js, sess, prekeys, responderID.PublicKey); err == nil {
		t.Fatal("ReceiveSession: expected an error for a corrupt stream")
	}

	if _, err := os.Stat(destDir); !os.IsNotExist(err) {
		t.Error("destDir should not have been created for a failed transfer")
	}
	sandboxDir := pipeline.SandboxPath(destDir, sess.ID)
	if _, err := os.Stat(sandboxDir); !os.IsNotExist(err) {
		t.Error("sandbox should have been cleaned up after a failed transfer")
	}

	st := waitStatus(t, statusCh)
	if st.Completed {
		t.Error("status.Completed = true, want false")
	}
	if st.Error == "" {
		t.Error("status.Error should be set on failure")
	}
}

// publishOnceStreamExists waits for ReceiveSession to have created the
// stream (it races the send goroutine on purpose, mirroring how the real
// Daemon and CLI run as separate processes with no shared ordering
// guarantee beyond "the approved handshake happened first") before
// publishing into it. enc may be nil for a plaintext transfer.
func publishOnceStreamExists(ctx context.Context, js jetstream.JetStream, sessionID string, r io.Reader, enc *pipeline.Encryption) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := js.Stream(ctx, fsnats.StreamName(sessionID)); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return context.DeadlineExceeded
		}
		time.Sleep(20 * time.Millisecond)
	}
	return pipeline.PublishArchive(ctx, js, fsnats.StreamSubject(sessionID), r, pipeline.DefaultChunkSize, enc)
}

func subscribeStatus(t *testing.T, conn *natsgo.Conn, sessionID string) <-chan daemon.Status {
	t.Helper()
	ch := make(chan daemon.Status, 1)
	sub, err := conn.Subscribe(fsnats.StatusSubject(sessionID), func(msg *natsgo.Msg) {
		var st daemon.Status
		if err := json.Unmarshal(msg.Data, &st); err != nil {
			return
		}
		ch <- st
	})
	if err != nil {
		t.Fatalf("subscribe status: %v", err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return ch
}

func waitStatus(t *testing.T, ch <-chan daemon.Status) daemon.Status {
	t.Helper()
	select {
	case st := <-ch:
		return st
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for status message")
		return daemon.Status{}
	}
}
