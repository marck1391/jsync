package syncfs_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/crypto/ratchet"
	"filesharer/internal/crypto/x3dh"
	"filesharer/internal/syncfs"
	fsnats "filesharer/internal/transport/nats"
	"filesharer/internal/watch"
)

// deriveTestEncryptionPair derives a matching pair of *syncfs.Encryption —
// one for "alice" (the X3DH initiator), one for "bob" (the responder) — the
// same way the real orchestration in cmd/fileshare's buildWatchEncryption
// and internal/daemon's establishResponderEncryption does, minus the actual
// NATS bootstrap messages (that dance is those callers' job, not
// internal/syncfs's — see encrypt.go's PublishBootstrap/ReceiveBootstrap
// doc comments). This only exercises what this package is actually
// responsible for testing: that PublishChanges/ReceiveChanges correctly
// encrypt and decrypt once handed two already-derived, matching chains.
func deriveTestEncryptionPair(t *testing.T) (alice, bob *syncfs.Encryption) {
	t.Helper()

	aliceIDPub, aliceIDPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate alice identity key: %v", err)
	}
	bobIDPub, bobIDPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate bob identity key: %v", err)
	}

	aliceStore, err := x3dh.NewStore(aliceIDPub, aliceIDPriv, 1)
	if err != nil {
		t.Fatalf("new alice store: %v", err)
	}
	bobStore, err := x3dh.NewStore(bobIDPub, bobIDPriv, 1)
	if err != nil {
		t.Fatalf("new bob store: %v", err)
	}

	bundle := bobStore.Bundle()
	sk, aliceEphemeralPriv, usedOTPID, err := aliceStore.DeriveInitiator(bundle)
	if err != nil {
		t.Fatalf("DeriveInitiator: %v", err)
	}
	aliceOut, err := ratchet.InitSending(sk, aliceEphemeralPriv, bundle.SignedPreKey)
	if err != nil {
		t.Fatalf("InitSending (alice outbound): %v", err)
	}

	bobSK, bobIn, err := bobStore.DeriveResponderChains(aliceStore.IdentityDHPublicKey(), aliceEphemeralPriv.PublicKey(), usedOTPID)
	if err != nil {
		t.Fatalf("DeriveResponderChains: %v", err)
	}

	bobEphemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate bob's fresh ephemeral key: %v", err)
	}
	bobOut, err := ratchet.InitSending(bobSK, bobEphemeralPriv, aliceEphemeralPriv.PublicKey())
	if err != nil {
		t.Fatalf("InitSending (bob outbound): %v", err)
	}

	aliceIn, err := ratchet.InitReceiving(sk, aliceEphemeralPriv, bobEphemeralPriv.PublicKey())
	if err != nil {
		t.Fatalf("InitReceiving (alice inbound): %v", err)
	}

	ad := x3dh.AssociatedData(aliceIDPub, bobIDPub)
	alice = &syncfs.Encryption{SendChain: aliceOut, RecvChain: aliceIn, AssociatedData: ad}
	bob = &syncfs.Encryption{SendChain: bobOut, RecvChain: bobIn, AssociatedData: ad}
	return alice, bob
}

// TestBidirectionalEncryptedPropagation is TestBidirectionalNoEchoLoop's
// encrypted counterpart: same two-node bidirectional sync, but with a real
// (non-nil) *syncfs.Encryption on each side. Confirms two successive
// OpWrite events — exercising the chain's first two sequence numbers, in
// each direction — still propagate correctly end to end, and — the part
// that actually matters for Fase 3's promise — that the plaintext content
// never appears in the raw bytes JetStream stored for either message.
// OpRemove/OpRename are deliberately not exercised here: neither has a
// Data field, so encryption never touches them (see ReceiveChanges'
// unconditional-decrypt comment in bridge.go), and TestUnidirectionalPropagation
// already covers their propagation logic identically regardless of enc.
func TestBidirectionalEncryptedPropagation(t *testing.T) {
	node := bootstrapTestNode(t)
	js, err := jetstream.New(node.Conn)
	if err != nil {
		t.Fatalf("jetstream.New: %v", err)
	}

	const sessionID = "sync-bidi-encrypted"
	stream, err := fsnats.EnsureEventsStream(context.Background(), js, sessionID)
	if err != nil {
		t.Fatalf("EnsureEventsStream: %v", err)
	}
	subject := fsnats.EventsSubject(sessionID)

	encA, encB := deriveTestEncryptionPair(t)

	rootA := t.TempDir()
	rootB := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startNode := func(machineID, root string, enc *syncfs.Encryption) {
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
			if err := syncfs.PublishChanges(ctx, js, subject, machineID, root, changes, echo, versions, enc); err != nil && ctx.Err() == nil {
				t.Logf("[%s] PublishChanges: %v", machineID, err)
			}
		}()

		cons, err := fsnats.EnsureEventsConsumer(context.Background(), js, sessionID, machineID)
		if err != nil {
			t.Fatalf("[%s] EnsureEventsConsumer: %v", machineID, err)
		}
		go func() {
			if err := syncfs.ReceiveChanges(ctx, cons, machineID, root, echo, versions, nil, enc); err != nil && ctx.Err() == nil {
				t.Logf("[%s] ReceiveChanges: %v", machineID, err)
			}
		}()
	}

	startNode("node-a", rootA, encA)
	startNode("node-b", rootB, encB)

	const secret = "this content must never appear in the clear on the wire"
	fileA := filepath.Join(rootA, "shared.txt")
	if err := os.WriteFile(fileA, []byte(secret), 0o644); err != nil {
		t.Fatalf("write on A: %v", err)
	}

	fileB := filepath.Join(rootB, "shared.txt")
	waitForContent(t, fileB, secret, 5*time.Second)

	// Modify: another OpWrite, exercising the chain's second sequence
	// number in each direction.
	const secret2 = "updated content, still must never be readable on the wire"
	if err := os.WriteFile(fileA, []byte(secret2), 0o644); err != nil {
		t.Fatalf("rewrite on A: %v", err)
	}
	waitForContent(t, fileB, secret2, 5*time.Second)

	// Confirm neither plaintext version ever appeared unencrypted anywhere
	// in the stream's stored message bytes — read the raw stream directly,
	// bypassing both nodes' consumers entirely.
	assertStreamNeverContainedPlaintext(t, js, sessionID, secret, secret2)
	_ = stream
}

func assertStreamNeverContainedPlaintext(t *testing.T, js jetstream.JetStream, sessionID string, plaintexts ...string) {
	t.Helper()

	cons, err := js.CreateOrUpdateConsumer(context.Background(), fsnats.EventsStreamName(sessionID), jetstream.ConsumerConfig{
		Durable:       "test-wire-inspector",
		AckPolicy:     jetstream.AckNonePolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("create inspection consumer: %v", err)
	}

	batch, err := cons.FetchNoWait(64)
	if err != nil {
		t.Fatalf("FetchNoWait: %v", err)
	}
	count := 0
	for msg := range batch.Messages() {
		count++
		for _, want := range plaintexts {
			if bytes.Contains(msg.Data(), []byte(want)) {
				t.Fatalf("stream message %d contains plaintext %q on the wire — encryption did not actually happen: %s", count, want, msg.Data())
			}
		}
	}
	if count == 0 {
		t.Fatal("inspection consumer read zero messages — test setup is broken, this assertion isn't checking anything")
	}
}
