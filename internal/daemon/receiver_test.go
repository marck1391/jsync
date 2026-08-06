package daemon_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
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
		ar := pipeline.NewArchiveReader(srcRoot, nil)
		defer ar.Close()
		sendDone <- publishOnceStreamExists(ctx, js, sess.ID, ar, nil)
	}()

	if err := daemon.ReceiveSession(ctx, node.Conn, js, sess, prekeys, responderID.PublicKey, daemon.NewResumeRegistry()); err != nil {
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
		ar := pipeline.NewArchiveReader(srcRoot, nil)
		defer ar.Close()
		sendDone <- publishOnceStreamExists(ctx, js, sess.ID, ar, enc)
	}()

	if err := daemon.ReceiveSession(ctx, node.Conn, js, sess, prekeys, responderID.PublicKey, daemon.NewResumeRegistry()); err != nil {
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

// TestReceiveSessionCorruptStreamParksSandboxForResume replaces what used
// to be TestReceiveSessionCorruptStreamFailsAndCleansUp: a failed transfer
// no longer deletes its sandbox outright (Fase 2 "recuperación de red") —
// it parks it in the ResumeRegistry so a later attempt from the same peer
// can reclaim it, and only the watchdog sweep (cmd/fileshared), once the
// grace period actually passes, deletes it for good. This test's own
// ResumeRegistry is never swept, so the sandbox must still be there
// afterward — the opposite assertion from what this test used to make.
func TestReceiveSessionCorruptStreamParksSandboxForResume(t *testing.T) {
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
	destDir := filepath.Join(dir, "final", "dest")
	sess := &handshake.Session{ID: "sess-corrupt", DestPath: destDir, PeerPublicKey: initiatorID.PublicKey}
	resumes := daemon.NewResumeRegistry()

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

	if err := daemon.ReceiveSession(ctx, node.Conn, js, sess, prekeys, responderID.PublicKey, resumes); err == nil {
		t.Fatal("ReceiveSession: expected an error for a corrupt stream")
	}

	if _, err := os.Stat(destDir); !os.IsNotExist(err) {
		t.Error("destDir should not have been created for a failed transfer")
	}
	sandboxDir := pipeline.SandboxPath(destDir, sess.ID)
	if _, err := os.Stat(sandboxDir); os.IsNotExist(err) {
		t.Error("sandbox should have been parked for resume, not deleted, after a failed transfer")
	}

	if sandboxDir, _, ok := resumes.Claim(initiatorID.PublicKey, destDir); !ok {
		t.Error("resume registry should have an entry for this peer+destPath after the failure")
	} else if sandboxDir == "" {
		t.Error("parked entry's sandboxDir should not be empty")
	}

	st := waitStatus(t, statusCh)
	if st.Completed {
		t.Error("status.Completed = true, want false")
	}
	if st.Error == "" {
		t.Error("status.Error should be set on failure")
	}
}

// TestReceiveSessionResumesAfterPark is the end-to-end proof of Fase 2's
// "recuperación de red": a first attempt is cut short mid-stream (as if
// the sender's process died partway through, or the network dropped) and
// its sandbox gets parked instead of deleted; a second attempt — a fresh
// handshake.Session (different ID, same peer identity and destPath, the
// way a relaunched `fileshare share` looks from the daemon's side) sends
// only the one file a real resume-aware sender would still need to send
// (built via pipeline.NewArchiveReader's own skip parameter, ResumedFiles'
// eventual sender-side consumer) and reclaims the parked sandbox. The
// final committed destDir must have all three files correct — two of them
// never present in the second attempt's archive at all, proving they
// really did survive from the first attempt rather than being silently
// re-sent.
func TestReceiveSessionResumesAfterPark(t *testing.T) {
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
	resumes := daemon.NewResumeRegistry()

	dir := t.TempDir()
	srcRoot := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcRoot, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	const aContent = "small a"
	const bContent = "small b"
	bigContent := strings.Repeat("z", 256*1024)
	for rel, content := range map[string]string{"a.txt": aContent, "b.txt": bContent, "z_big.txt": bigContent} {
		if err := os.WriteFile(filepath.Join(srcRoot, rel), []byte(content), 0o644); err != nil {
			t.Fatalf("setup write %s: %v", rel, err)
		}
	}
	destDir := filepath.Join(dir, "final", "dest")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// --- Attempt 1: cut short partway through, simulating a dead sender. ---
	full, err := io.ReadAll(pipeline.NewArchiveReader(srcRoot, nil))
	if err != nil {
		t.Fatalf("read full archive: %v", err)
	}
	truncated := full[:len(full)/2]

	sess1 := &handshake.Session{ID: "sess-resume-1", DestPath: destDir, PeerPublicKey: initiatorID.PublicKey}
	statusCh1 := subscribeStatus(t, node.Conn, sess1.ID)

	send1Done := make(chan error, 1)
	go func() {
		send1Done <- publishOnceStreamExists(ctx, js, sess1.ID, bytes.NewReader(truncated), nil)
	}()

	if err := daemon.ReceiveSession(ctx, node.Conn, js, sess1, prekeys, responderID.PublicKey, resumes); err == nil {
		t.Fatal("ReceiveSession (attempt 1): expected an error for a truncated stream")
	}
	if err := <-send1Done; err != nil {
		t.Fatalf("send (attempt 1): %v", err)
	}
	st1 := waitStatus(t, statusCh1)
	if st1.Completed {
		t.Error("attempt 1: status.Completed = true, want false")
	}

	resumed := resumes.Peek(initiatorID.PublicKey, destDir)
	gotResumed := map[string]string{}
	for _, rf := range resumed {
		gotResumed[rf.RelPath] = rf.ContentHash
	}
	wantHash := func(content string) string {
		sum := sha256.Sum256([]byte(content))
		return hex.EncodeToString(sum[:])
	}
	if gotResumed["a.txt"] != wantHash(aContent) {
		t.Errorf("resume manifest a.txt hash = %q, want %q", gotResumed["a.txt"], wantHash(aContent))
	}
	if gotResumed["b.txt"] != wantHash(bContent) {
		t.Errorf("resume manifest b.txt hash = %q, want %q", gotResumed["b.txt"], wantHash(bContent))
	}
	if _, present := gotResumed["z_big.txt"]; present {
		t.Error("z_big.txt should not be in the resume manifest — it was cut off mid-copy in attempt 1")
	}

	// --- Attempt 2: a fresh session, only sending what attempt 1 doesn't
	// already have (exactly what a real resuming sender would compute from
	// Response.ResumedFiles via pipeline.NewArchiveReader's skip param). ---
	skip := map[string]string{"a.txt": wantHash(aContent), "b.txt": wantHash(bContent)}
	partial := pipeline.NewArchiveReader(srcRoot, skip)

	sess2 := &handshake.Session{ID: "sess-resume-2", DestPath: destDir, PeerPublicKey: initiatorID.PublicKey}
	statusCh2 := subscribeStatus(t, node.Conn, sess2.ID)

	send2Done := make(chan error, 1)
	go func() {
		send2Done <- publishOnceStreamExists(ctx, js, sess2.ID, partial, nil)
	}()

	if err := daemon.ReceiveSession(ctx, node.Conn, js, sess2, prekeys, responderID.PublicKey, resumes); err != nil {
		t.Fatalf("ReceiveSession (attempt 2): %v", err)
	}
	if err := <-send2Done; err != nil {
		t.Fatalf("send (attempt 2): %v", err)
	}
	st2 := waitStatus(t, statusCh2)
	if !st2.Completed {
		t.Errorf("attempt 2: status.Completed = false, want true (error: %s)", st2.Error)
	}

	for rel, want := range map[string]string{"a.txt": aContent, "b.txt": bContent, "z_big.txt": bigContent} {
		got, err := os.ReadFile(filepath.Join(destDir, rel))
		if err != nil {
			t.Fatalf("read committed %s: %v", rel, err)
		}
		if string(got) != want {
			t.Errorf("%s content mismatch after resume (len got=%d, want=%d)", rel, len(got), len(want))
		}
	}

	sandboxDir1 := pipeline.SandboxPath(destDir, sess1.ID)
	if _, err := os.Stat(sandboxDir1); !os.IsNotExist(err) {
		t.Error("attempt 1's sandbox should be gone (renamed into destDir by attempt 2's commit), not left behind")
	}
	if _, _, ok := resumes.Claim(initiatorID.PublicKey, destDir); ok {
		t.Error("resume registry should have nothing parked after a successful resumed transfer")
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
	return pipeline.PublishArchive(ctx, js, fsnats.StreamSubject(sessionID), r, pipeline.DefaultChunkSize, enc, 0)
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
