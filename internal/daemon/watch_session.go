package daemon

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/crypto/ratchet"
	"filesharer/internal/crypto/x3dh"
	"filesharer/internal/handshake"
	"filesharer/internal/ignore"
	"filesharer/internal/syncfs"
	fsnats "filesharer/internal/transport/nats"
	"filesharer/internal/watch"
)

// bootstrapTimeout bounds how long an encrypted WatchSession waits for the
// initiator's Fase 3 bootstrap message before giving up — generous next to
// eventFetchTimeout's 2s per-Fetch poll (bridge.go), but still bounded: a
// well-behaved initiator that requested RequestedEncrypt always sends its
// bootstrap before anything else, so a wait this long past that point means
// something is actually wrong, not just slow.
const bootstrapTimeout = 15 * time.Second

// WatchSession runs the Fase 5 receiving side for one approved bidirectional
// handshake session: creates the session's events stream and this node's
// own durable consumer on it, starts a native Watcher on sess.DestPath, and
// bridges both directions (its own local changes out, the peer's changes
// in) exactly the way cmd/fileshare's `watch` does on the initiator's side
// — the Watcher session is symmetric, neither end is privileged. Runs
// until ctx is done (the Daemon shutting down) or an unrecoverable error;
// unlike ReceiveSession there is no natural "done" point for a live sync.
//
// prekeys is this node's own X3DH material, used only if sess.Params.Encrypt
// (the initiator asked for --encrypt); localIdentityPub is this node's
// Ed25519 identity key, needed for the Double Ratchet's Associated Data —
// same two arguments ReceiveSession already takes for the same reason
// (Fase 3).
func WatchSession(ctx context.Context, conn *natsgo.Conn, js jetstream.JetStream, sess *handshake.Session, localMachineID string, prekeys *x3dh.Store, localIdentityPub ed25519.PublicKey) error {
	if err := os.MkdirAll(sess.DestPath, 0o755); err != nil {
		return fmt.Errorf("daemon: create watch root %s: %w", sess.DestPath, err)
	}

	if _, err := fsnats.EnsureEventsStream(ctx, js, sess.ID); err != nil {
		return fmt.Errorf("daemon: ensure events stream: %w", err)
	}
	cons, err := fsnats.EnsureEventsConsumer(ctx, js, sess.ID, localMachineID)
	if err != nil {
		return fmt.Errorf("daemon: ensure events consumer: %w", err)
	}
	subject := fsnats.EventsSubject(sess.ID)

	// Encryption, if requested, must be fully established — both chains
	// derived — before this node's own Watcher starts, or a real Event
	// could reach PublishChanges/ReceiveChanges before there's a chain to
	// encrypt/decrypt it with. See internal/syncfs/encrypt.go.
	var enc *syncfs.Encryption
	if sess.Params.Encrypt {
		enc, err = establishResponderEncryption(ctx, js, cons, subject, sess, localMachineID, prekeys, localIdentityPub)
		if err != nil {
			return fmt.Errorf("daemon: watch session %s: establish encryption: %w", sess.ID, err)
		}
	}

	matcher, err := ignore.Load(sess.DestPath)
	if err != nil {
		return fmt.Errorf("daemon: load %s: %w", ignore.FileName, err)
	}
	fw := watch.NewFileWatcher(watch.DefaultDebounce, watch.DefaultBufferSize, matcher)
	defer fw.Close()
	changes, watchErrs := fw.Watch(ctx, sess.DestPath)
	go func() {
		for err := range watchErrs {
			fmt.Fprintf(os.Stderr, "fileshared: watch session %s: local watch error: %v\n", sess.ID, err)
		}
	}()

	echo := syncfs.NewEchoGuard()
	versions := syncfs.NewVersionStore()

	onConflict := func(ev syncfs.Event, conflictPath string) {
		fmt.Fprintf(os.Stderr, "fileshared: watch session %s: conflict on %s, wrote %s — resolve manually\n", sess.ID, ev.RelPath, conflictPath)
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- syncfs.PublishChanges(ctx, js, subject, localMachineID, sess.DestPath, changes, echo, versions, enc)
	}()
	go func() {
		errCh <- syncfs.ReceiveChanges(ctx, cons, localMachineID, sess.DestPath, echo, versions, onConflict, enc)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return fmt.Errorf("daemon: watch session %s ended: %w", sess.ID, err)
		}
		return nil
	}
}

// establishResponderEncryption runs the responder ("Bob") half of Fase 5's
// bootstrap dance: wait for the initiator's OpBootstrap, mirror its sending
// chain into our own receiving chain, generate a fresh ephemeral keypair
// for our own sending chain (a real DH step, not a reuse of the X3DH
// output both chains would otherwise share — see encrypt.go's Encryption
// doc comment for why that matters), and publish OpBootstrapAck so the
// initiator can complete its side. See internal/crypto/x3dh.x3dh.go's
// DeriveResponderChains doc for why sk is only obtainable this way (once,
// alongside the receiving chain) without double-consuming the One-Time
// PreKey deriveResponder spends.
func establishResponderEncryption(ctx context.Context, js jetstream.JetStream, cons jetstream.Consumer, subject string, sess *handshake.Session, localMachineID string, prekeys *x3dh.Store, localIdentityPub ed25519.PublicKey) (*syncfs.Encryption, error) {
	bootCtx, cancel := context.WithTimeout(ctx, bootstrapTimeout)
	defer cancel()

	initiatorDHPubBytes, ephemeralPubBytes, usedOTPID, err := syncfs.ReceiveBootstrap(bootCtx, cons, sess.PeerMachineID)
	if err != nil {
		return nil, fmt.Errorf("receive bootstrap: %w", err)
	}
	initiatorDHPub, err := ecdh.X25519().NewPublicKey(initiatorDHPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse initiator identity DH key: %w", err)
	}
	ephemeralPub, err := ecdh.X25519().NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse initiator ephemeral key: %w", err)
	}

	sk, inbound, err := prekeys.DeriveResponderChains(initiatorDHPub, ephemeralPub, usedOTPID)
	if err != nil {
		return nil, fmt.Errorf("X3DH: %w", err)
	}

	freshPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate outbound ratchet key: %w", err)
	}
	outbound, err := ratchet.InitSending(sk, freshPriv, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("init outbound chain: %w", err)
	}

	if err := syncfs.PublishBootstrapAck(bootCtx, js, subject, localMachineID, freshPriv.PublicKey().Bytes()); err != nil {
		return nil, fmt.Errorf("publish bootstrap ack: %w", err)
	}

	return &syncfs.Encryption{
		SendChain:      outbound,
		RecvChain:      inbound,
		AssociatedData: x3dh.AssociatedData(sess.PeerPublicKey, localIdentityPub),
	}, nil
}
