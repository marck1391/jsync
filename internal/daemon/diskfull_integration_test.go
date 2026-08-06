package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/crypto/x3dh"
	"filesharer/internal/handshake"
	"filesharer/internal/identity"
	"filesharer/internal/pipeline"
	fsnats "filesharer/internal/transport/nats"
)

// TestReceiveSessionAbortsInsteadOfParkingOnDiskFull is the integration
// counterpart to isDiskFullPlatform's own unit tests (diskfull_unix_test.go
// / diskfull_windows_test.go): it proves ReceiveSession actually takes the
// abort-not-park branch when isDiskFull says so, rather than just proving
// the classifier itself works in isolation. isDiskFull is a package var
// specifically so this can substitute a fake classifier instead of needing
// to genuinely exhaust a disk — same technique, same package, as
// resume_test.go's tests of ResumeRegistry in isolation. The underlying
// failure here is an ordinary corrupt stream (mirroring
// TestReceiveSessionCorruptStreamParksSandboxForResume in receiver_test.go)
// — what actually broke doesn't matter, since isDiskFull is stubbed to
// always report true regardless.
func TestReceiveSessionAbortsInsteadOfParkingOnDiskFull(t *testing.T) {
	orig := isDiskFull
	isDiskFull = func(err error) bool { return true }
	defer func() { isDiskFull = orig }()

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
	destDir := filepath.Join(dir, "final", "dest")
	sess := &handshake.Session{ID: "sess-diskfull", DestPath: destDir, PeerPublicKey: initiatorID.PublicKey}
	resumes := NewResumeRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := fsnats.EnsureStream(ctx, js, sess.ID); err != nil {
		t.Fatalf("EnsureStream: %v", err)
	}
	msg := &natsgo.Msg{Subject: fsnats.StreamSubject(sess.ID), Data: []byte("not gzip data")}
	msg.Header = natsgo.Header{}
	msg.Header.Set(pipeline.HeaderChunkSequence, "0")
	msg.Header.Set(pipeline.HeaderIsFinalChunk, "true")
	if _, err := js.PublishMsg(ctx, msg); err != nil {
		t.Fatalf("publish corrupt chunk: %v", err)
	}

	if err := ReceiveSession(ctx, node.Conn, js, sess, prekeys, responderID.PublicKey, resumes); err == nil {
		t.Fatal("ReceiveSession: expected an error")
	}

	sandboxDir := pipeline.SandboxPath(destDir, sess.ID)
	if _, err := os.Stat(sandboxDir); !os.IsNotExist(err) {
		t.Error("sandbox should have been deleted immediately (disk-full classified), not parked")
	}
	if _, _, ok := resumes.Claim(initiatorID.PublicKey, destDir); ok {
		t.Error("resume registry should have nothing parked when the failure was classified as disk-full")
	}
}
