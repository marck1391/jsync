// Command fileshare is the CLI client: a short-lived process that talks to
// the local or remote fileshared node over NATS to trigger one-off
// operations (share, pull, watch, resolve, keys) — it does not itself keep
// any long-running state, that belongs to the daemon (Fase 4).
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/config"
	"filesharer/internal/crypto/ratchet"
	"filesharer/internal/crypto/x3dh"
	"filesharer/internal/daemon"
	"filesharer/internal/handshake"
	"filesharer/internal/identity"
	"filesharer/internal/ignore"
	"filesharer/internal/pipeline"
	"filesharer/internal/syncfs"
	fsnats "filesharer/internal/transport/nats"
	"filesharer/internal/watch"
)

type subcommand struct {
	name  string
	usage string
	run   func(args []string) error
}

var subcommands = []subcommand{
	{"share", "fileshare share [--config path] <local-path> <target-machine-id>:<dest-path>", cmdShare},
	{"pull", "fileshare pull <target-machine-id>:<path> <dest>", blockedOnPhase("Fase 2 (motor de streaming)")},
	{"watch", "fileshare watch [--config path] <local-path> <target-machine-id>:<dest-path>", cmdWatch},
	{"resolve", "fileshare resolve <conflict-file>", blockedOnPhase("Fase 5 (conflictos)")},
	{"keys", "fileshare keys [--config path] generate|show|authorize <base64-pubkey>", cmdKeys},
}

func blockedOnPhase(phase string) func([]string) error {
	return func(args []string) error {
		return fmt.Errorf("not implemented yet — needs %s", phase)
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	name := os.Args[1]
	for _, sc := range subcommands {
		if sc.name != name {
			continue
		}
		if err := sc.run(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "fileshare %s: %v\n", name, err)
			os.Exit(1)
		}
		return
	}

	fmt.Fprintf(os.Stderr, "fileshare: unknown command %q\n\n", name)
	printUsage()
	os.Exit(1)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	for _, sc := range subcommands {
		fmt.Fprintf(os.Stderr, "  %s\n", sc.usage)
	}
}

// loadLocalIdentity reads config.yaml (or its defaults) and this node's
// identity — the same first-boot-generates pattern fileshared uses, so a
// bare `fileshare` invocation on a fresh machine works without any setup
// beyond `fileshare keys show` to hand your public key to whoever you want
// to talk to.
func loadLocalIdentity(cfgPath string) (*config.Config, *identity.Identity, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}

	machineID := cfg.MachineID
	if machineID == "" {
		machineID, err = identity.NewMachineID()
		if err != nil {
			return nil, nil, fmt.Errorf("generate machine id: %w", err)
		}
	}

	id, err := identity.Load(cfg.IdentityPath, machineID)
	if err != nil {
		return nil, nil, fmt.Errorf("load identity: %w", err)
	}
	return cfg, id, nil
}

func cmdKeys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.yaml", "path to daemon config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: fileshare keys generate|show|authorize <base64-pubkey>")
	}

	cfg, id, err := loadLocalIdentity(*cfgPath)
	if err != nil {
		return err
	}

	switch rest[0] {
	case "generate", "show":
		// Load already generated-and-persisted it if this is the first
		// run; both subcommands just print the current identity.
		fmt.Println("machine_id:", id.MachineID)
		fmt.Println("public_key:", base64.StdEncoding.EncodeToString(id.PublicKey))
		return nil

	case "authorize":
		if len(rest) < 2 {
			return fmt.Errorf("usage: fileshare keys authorize <base64-pubkey>")
		}
		raw, err := base64.StdEncoding.DecodeString(rest[1])
		if err != nil {
			return fmt.Errorf("decode public key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
		}

		authorized, err := identity.LoadAuthorizedClients(cfg.AuthorizedClientsPath)
		if err != nil {
			return fmt.Errorf("load authorized_clients: %w", err)
		}
		if err := authorized.Add(ed25519.PublicKey(raw)); err != nil {
			return fmt.Errorf("authorize key: %w", err)
		}
		fmt.Println("authorized:", rest[1])
		return nil

	default:
		return fmt.Errorf("unknown keys subcommand %q (want generate, show, or authorize)", rest[0])
	}
}

// buildEncryption loads this node's own X3DH material (the same
// prekeys.json a fileshared responder would use, generated on first use if
// it doesn't exist yet — a plain `fileshare share` never needs to have run
// `fileshared` first) and runs the initiator side of X3DH against the
// responder's bundle from the handshake response, returning a ready
// pipeline.Encryption for PublishArchive.
func buildEncryption(cfg *config.Config, id *identity.Identity, bundle x3dh.Bundle) (*pipeline.Encryption, error) {
	store, err := x3dh.LoadStore(cfg.PrekeysPath, id.PublicKey, id.PrivateKey, cfg.OneTimePreKeyCount)
	if err != nil {
		return nil, fmt.Errorf("load prekeys: %w", err)
	}

	chain, ephemeralPub, usedOTPID, err := store.DeriveInitiatorChain(bundle)
	if err != nil {
		return nil, fmt.Errorf("X3DH: %w", err)
	}

	return &pipeline.Encryption{
		Chain:          chain,
		AssociatedData: x3dh.AssociatedData(id.PublicKey, bundle.IdentityKey),
		Bootstrap: pipeline.EncryptionBootstrap{
			InitiatorDHPub: store.IdentityDHPublicKey(),
			EphemeralPub:   ephemeralPub,
			UsedOTPID:      usedOTPID,
		},
	}, nil
}

// buildWatchEncryption is buildEncryption's Fase 5 counterpart: a live
// watch session is bidirectional, so it needs two independent chains, not
// buildEncryption's one (see internal/syncfs/encrypt.go's Encryption doc
// comment for why sharing one chain both directions would be an AES-GCM
// nonce-reuse bug). It runs the initiator ("Alice") half of the bootstrap
// dance: derive X3DH as usual, build the outbound chain from that exactly
// like buildEncryption does, publish OpBootstrap so the responder can
// mirror it, then block for the responder's OpBootstrapAck — its own fresh
// ratchet key — and use that (against the same ephemeralPriv X3DH already
// generated) to derive the inbound chain. cons must already be this node's
// events consumer (from fsnats.EnsureEventsConsumer) so ReceiveBootstrapAck
// can read the responder's reply off it.
func buildWatchEncryption(ctx context.Context, cfg *config.Config, id *identity.Identity, bundle x3dh.Bundle, js jetstream.JetStream, cons jetstream.Consumer, subject, peerMachineID string) (*syncfs.Encryption, error) {
	store, err := x3dh.LoadStore(cfg.PrekeysPath, id.PublicKey, id.PrivateKey, cfg.OneTimePreKeyCount)
	if err != nil {
		return nil, fmt.Errorf("load prekeys: %w", err)
	}

	sk, ephemeralPriv, usedOTPID, err := store.DeriveInitiator(bundle)
	if err != nil {
		return nil, fmt.Errorf("X3DH: %w", err)
	}
	outbound, err := ratchet.InitSending(sk, ephemeralPriv, bundle.SignedPreKey)
	if err != nil {
		return nil, fmt.Errorf("init outbound chain: %w", err)
	}

	bootCtx, cancel := context.WithTimeout(ctx, watchBootstrapTimeout)
	defer cancel()

	if err := syncfs.PublishBootstrap(bootCtx, js, subject, id.MachineID, store.IdentityDHPublicKey().Bytes(), ephemeralPriv.PublicKey().Bytes(), usedOTPID); err != nil {
		return nil, fmt.Errorf("publish bootstrap: %w", err)
	}

	responderEphemeralPubBytes, err := syncfs.ReceiveBootstrapAck(bootCtx, cons, peerMachineID)
	if err != nil {
		return nil, fmt.Errorf("receive bootstrap ack: %w", err)
	}
	responderEphemeralPub, err := ecdh.X25519().NewPublicKey(responderEphemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse responder ephemeral key: %w", err)
	}
	inbound, err := ratchet.InitReceiving(sk, ephemeralPriv, responderEphemeralPub)
	if err != nil {
		return nil, fmt.Errorf("init inbound chain: %w", err)
	}

	return &syncfs.Encryption{
		SendChain:      outbound,
		RecvChain:      inbound,
		AssociatedData: x3dh.AssociatedData(id.PublicKey, bundle.IdentityKey),
	}, nil
}

func cmdShare(args []string) error {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.yaml", "path to daemon config file")
	timeout := fs.Duration("timeout", 10*time.Second, "handshake timeout")
	transferTimeout := fs.Duration("transfer-timeout", 2*time.Minute, "how long to wait for the transfer to finish after the handshake is approved")
	encrypt := fs.Bool("encrypt", false, "end-to-end encrypt the transfer (Fase 3: X3DH + Double Ratchet, chunk contents unreadable to the NATS broker)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 2 {
		return fmt.Errorf("usage: fileshare share [--config path] <local-path> <target-machine-id>:<dest-path>")
	}
	srcPath, target := rest[0], rest[1]

	targetMachineID, destPath, ok := strings.Cut(target, ":")
	if !ok || targetMachineID == "" || destPath == "" {
		return fmt.Errorf("target must be <machine-id>:<dest-path>, got %q", target)
	}
	if _, err := os.Stat(srcPath); err != nil {
		return fmt.Errorf("local path: %w", err)
	}

	cfg, id, err := loadLocalIdentity(*cfgPath)
	if err != nil {
		return err
	}

	// fileshare is a short-lived client of the fileshared daemon already
	// running on this machine (Fase 4) — it connects directly to that
	// daemon's plain client port instead of standing up its own embedded
	// NATS server/leaf link. Only the daemon needs to be a routable node
	// in the mesh (hub or peer); a one-shot CLI command just needs to
	// reach it, which is why cmdShare and cmdKeys share the same
	// config.yaml as the local fileshared: cfg.Host/cfg.Port is where
	// that daemon is already listening.
	brokerURL := fmt.Sprintf("nats://%s:%d", cfg.Host, cfg.Port)
	conn, err := natsgo.Connect(brokerURL)
	if err != nil {
		return fmt.Errorf("connect to local fileshared at %s: %w", brokerURL, err)
	}
	defer conn.Close()

	resp, err := fsnats.RequestHandshake(conn, id, targetMachineID, destPath, handshake.DirectionUnidirectional, false, *timeout)
	if err != nil {
		return fmt.Errorf("handshake with %s: %w", targetMachineID, err)
	}
	if !resp.Approved {
		return fmt.Errorf("handshake rejected by %s: %s", targetMachineID, resp.Reason)
	}
	if !resp.VerifyBundle() {
		return fmt.Errorf("handshake approved but %s's prekey bundle failed to verify — refusing to continue", targetMachineID)
	}

	fmt.Println("handshake approved, session_id:", resp.SessionID)

	js, err := jetstream.New(conn)
	if err != nil {
		return fmt.Errorf("init jetstream: %w", err)
	}

	// Subscribe to the completion status before publishing a single byte —
	// the daemon could in principle finish before we'd get around to
	// subscribing afterward, and NATS core pub/sub drops messages nobody
	// was listening for yet.
	statusCh := make(chan daemon.Status, 1)
	statusSub, err := conn.Subscribe(fsnats.StatusSubject(resp.SessionID), func(msg *natsgo.Msg) {
		var st daemon.Status
		if err := json.Unmarshal(msg.Data, &st); err == nil {
			statusCh <- st
		}
	})
	if err != nil {
		return fmt.Errorf("subscribe to transfer status: %w", err)
	}
	defer statusSub.Unsubscribe()

	var enc *pipeline.Encryption
	if *encrypt {
		enc, err = buildEncryption(cfg, id, resp.Bundle)
		if err != nil {
			return fmt.Errorf("set up encryption: %w", err)
		}
		fmt.Println("encryption: on (X3DH + Double Ratchet)")
	}

	ar := pipeline.NewArchiveReader(srcPath)
	defer ar.Close()

	pubCtx, cancel := context.WithTimeout(context.Background(), *transferTimeout)
	defer cancel()
	if err := pipeline.PublishArchive(pubCtx, js, fsnats.StreamSubject(resp.SessionID), ar, pipeline.DefaultChunkSize, enc); err != nil {
		return fmt.Errorf("send %s: %w", srcPath, err)
	}
	fmt.Println("all chunks sent, waiting for", targetMachineID, "to finish writing")

	select {
	case st := <-statusCh:
		if !st.Completed {
			return fmt.Errorf("%s failed to write %s: %s", targetMachineID, destPath, st.Error)
		}
		fmt.Printf("done: %s -> %s:%s\n", srcPath, targetMachineID, destPath)
		return nil
	case <-time.After(*transferTimeout):
		return fmt.Errorf("timed out after %s waiting for %s to confirm the write", *transferTimeout, targetMachineID)
	}
}

// watchBootstrapTimeout bounds how long the initiator waits for the
// responder's OpBootstrapAck (encrypt.go) during an encrypted watch
// session's setup — see internal/daemon's bootstrapTimeout for the same
// bound on the other side of this exchange.
const watchBootstrapTimeout = 15 * time.Second

// cmdWatch runs a live, bidirectional Fase 5 sync session: it handshakes
// with DirectionBidirectional (fileshared's OnApproved starts a matching
// Watcher on its own side, see cmd/fileshared), then watches localPath and
// both publishes its own changes and applies the peer's, until interrupted
// (Ctrl+C / SIGTERM). With --encrypt, every event is end-to-end encrypted
// via Fase 3's X3DH + Double Ratchet before any of that starts — see
// buildWatchEncryption. There is still no initial reconciliation: it only
// reacts to changes from the moment it starts.
func cmdWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.yaml", "path to daemon config file")
	timeout := fs.Duration("timeout", 10*time.Second, "handshake timeout")
	encrypt := fs.Bool("encrypt", false, "end-to-end encrypt the session (Fase 3: X3DH + Double Ratchet, event contents unreadable to the NATS broker)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 2 {
		return fmt.Errorf("usage: fileshare watch [--config path] <local-path> <target-machine-id>:<dest-path>")
	}
	localPath, target := rest[0], rest[1]

	targetMachineID, destPath, ok := strings.Cut(target, ":")
	if !ok || targetMachineID == "" || destPath == "" {
		return fmt.Errorf("target must be <machine-id>:<dest-path>, got %q", target)
	}
	info, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("local path: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("local path %q must be a directory for watch", localPath)
	}

	cfg, id, err := loadLocalIdentity(*cfgPath)
	if err != nil {
		return err
	}

	brokerURL := fmt.Sprintf("nats://%s:%d", cfg.Host, cfg.Port)
	conn, err := natsgo.Connect(brokerURL)
	if err != nil {
		return fmt.Errorf("connect to local fileshared at %s: %w", brokerURL, err)
	}
	defer conn.Close()

	resp, err := fsnats.RequestHandshake(conn, id, targetMachineID, destPath, handshake.DirectionBidirectional, *encrypt, *timeout)
	if err != nil {
		return fmt.Errorf("handshake with %s: %w", targetMachineID, err)
	}
	if !resp.Approved {
		return fmt.Errorf("handshake rejected by %s: %s", targetMachineID, resp.Reason)
	}
	if !resp.VerifyBundle() {
		return fmt.Errorf("handshake approved but %s's prekey bundle failed to verify — refusing to continue", targetMachineID)
	}
	fmt.Println("handshake approved, session_id:", resp.SessionID)

	js, err := jetstream.New(conn)
	if err != nil {
		return fmt.Errorf("init jetstream: %w", err)
	}
	if _, err := fsnats.EnsureEventsStream(context.Background(), js, resp.SessionID); err != nil {
		return fmt.Errorf("ensure events stream: %w", err)
	}
	cons, err := fsnats.EnsureEventsConsumer(context.Background(), js, resp.SessionID, id.MachineID)
	if err != nil {
		return fmt.Errorf("ensure events consumer: %w", err)
	}
	subject := fsnats.EventsSubject(resp.SessionID)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Encryption, if requested, must be fully established — both chains
	// derived — before this node's own Watcher starts, or a real Event
	// could reach PublishChanges/ReceiveChanges before there's a chain to
	// encrypt/decrypt it with. See internal/syncfs/encrypt.go.
	var enc *syncfs.Encryption
	if *encrypt {
		enc, err = buildWatchEncryption(ctx, cfg, id, resp.Bundle, js, cons, subject, targetMachineID)
		if err != nil {
			return fmt.Errorf("set up encryption: %w", err)
		}
		fmt.Println("encryption: on (X3DH + Double Ratchet)")
	}

	matcher, err := ignore.Load(localPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", ignore.FileName, err)
	}
	fw := watch.NewFileWatcher(watch.DefaultDebounce, watch.DefaultBufferSize, matcher)
	changes, watchErrs := fw.Watch(ctx, localPath)
	defer fw.Close()
	go func() {
		for werr := range watchErrs {
			fmt.Fprintln(os.Stderr, "fileshare watch: local watch error:", werr)
		}
	}()

	echo := syncfs.NewEchoGuard()
	versions := syncfs.NewVersionStore()

	onConflict := func(ev syncfs.Event, conflictPath string) {
		fmt.Fprintf(os.Stderr, "fileshare watch: conflict on %s, wrote %s — resolve manually\n", ev.RelPath, conflictPath)
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- syncfs.PublishChanges(ctx, js, subject, id.MachineID, localPath, changes, echo, versions, enc)
	}()
	go func() {
		errCh <- syncfs.ReceiveChanges(ctx, cons, id.MachineID, localPath, echo, versions, onConflict, enc)
	}()

	fmt.Printf("watching %s <-> %s:%s (Ctrl+C to stop)\n", localPath, targetMachineID, destPath)

	select {
	case <-ctx.Done():
		fmt.Println("fileshare watch: stopping")
		return nil
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return fmt.Errorf("watch session ended: %w", err)
		}
		return nil
	}
}
