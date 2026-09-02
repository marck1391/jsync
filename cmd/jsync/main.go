// Command jsync is the CLI client: a short-lived process that talks to
// the local or remote jsyncd node over NATS to trigger one-off
// operations (share, pull, watch, resolve, keys) — it does not itself keep
// any long-running state, that belongs to the daemon (Fase 4).
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"jsync/internal/auditlog"
	"jsync/internal/config"
	"jsync/internal/crypto/ratchet"
	"jsync/internal/crypto/x3dh"
	"jsync/internal/daemon"
	"jsync/internal/handshake"
	"jsync/internal/identity"
	"jsync/internal/ignore"
	"jsync/internal/pipeline"
	"jsync/internal/progress"
	"jsync/internal/syncfs"
	fsnats "jsync/internal/transport/nats"
	"jsync/internal/watch"
)

type subcommand struct {
	name  string
	usage string
	run   func(args []string) error
}

var subcommands = []subcommand{
	{"share", "jsync share [--config path] <local-path> <target-machine-id>:<dest-path>", cmdShare},
	{"pull", "jsync pull <target-machine-id>:<path> <dest>", blockedOnPhase("Fase 2 (motor de streaming)")},
	{"watch", "jsync watch [--config path] <local-path> <target-machine-id>:<dest-path>", cmdWatch},
	{"log", "jsync log [--config path] [--session id] [--path substr] [--since when] [--json] [--files] [root]", cmdLog},
	{"allow", "jsync allow [--config path] <dest-path> | jsync allow --remove <dest-path> | jsync allow --list", cmdAllow},
	{"resolve", "jsync resolve <conflict-file>", blockedOnPhase("Fase 5 (conflictos)")},
	{"keys", "jsync keys [--config path] generate|show|authorize <base64-pubkey>", cmdKeys},
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
			fmt.Fprintf(os.Stderr, "jsync %s: %v\n", name, err)
			os.Exit(1)
		}
		return
	}

	fmt.Fprintf(os.Stderr, "jsync: unknown command %q\n\n", name)
	printUsage()
	os.Exit(1)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage:")
	for _, sc := range subcommands {
		fmt.Fprintf(os.Stderr, "  %s\n", sc.usage)
	}
}

// loadLocalIdentity resolves the config file (--config, else $JSYNC_CONFIG,
// else ./jsync.yaml, else ~/.config/jsync/config.yaml — see config.Resolve),
// reads it (or its defaults), and loads this node's identity — the same
// first-boot-generates pattern jsyncd uses, so a bare `jsync` invocation on
// a fresh machine works without any setup beyond `jsync keys show` to hand
// your public key to whoever you want to talk to.
func loadLocalIdentity(cfgPath string) (*config.Config, *identity.Identity, error) {
	resolved, _ := config.Resolve(cfgPath)
	cfg, err := config.Load(resolved)
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
	cfgPath := fs.String("config", "", "path to the jsync config file (default: ./jsync.yaml or ~/.config/jsync/config.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: jsync keys generate|show|authorize <base64-pubkey>")
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
			return fmt.Errorf("usage: jsync keys authorize <base64-pubkey>")
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
// prekeys.json a jsyncd responder would use, generated on first use if
// it doesn't exist yet — a plain `jsync share` never needs to have run
// `jsyncd` first) and runs the initiator side of X3DH against the
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

// fatalShareError marks a shareAttempt failure the retry loop in cmdShare
// must not retry — a policy rejection or a deterministic local error, not
// a transient network one. Retrying either would just be noisy, not
// resilient: the outcome would be identical every time.
type fatalShareError struct{ err error }

func (e *fatalShareError) Error() string { return e.err.Error() }
func (e *fatalShareError) Unwrap() error { return e.err }

func cmdShare(args []string) error {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to the jsync config file (default: ./jsync.yaml or ~/.config/jsync/config.yaml)")
	timeout := fs.Duration("timeout", 10*time.Second, "handshake timeout")
	transferTimeout := fs.Duration("transfer-timeout", 2*time.Minute, "how long to wait for the transfer to finish after the handshake is approved")
	encrypt := fs.Bool("encrypt", false, "end-to-end encrypt the transfer (Fase 3: X3DH + Double Ratchet, chunk contents unreadable to the NATS broker)")
	retries := fs.Int("retries", 2, "extra attempts (beyond the first) if a transfer fails for a retryable reason — network recovery (Fase 2) means a retry resumes automatically, skipping whatever the destination already has. 0 disables automatic retry")
	retryWait := fs.Duration("retry-wait", 3*time.Second, "how long to wait before an automatic retry")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 2 {
		return fmt.Errorf("usage: jsync share [--config path] <local-path> <target-machine-id>:<dest-path>")
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

	// jsync is a short-lived client of the jsyncd daemon already
	// running on this machine (Fase 4) — it connects directly to that
	// daemon's plain client port instead of standing up its own embedded
	// NATS server/leaf link. Only the daemon needs to be a routable node
	// in the mesh (hub or peer); a one-shot CLI command just needs to
	// reach it, which is why cmdShare and cmdKeys share the same
	// config.yaml as the local jsyncd: cfg.Host/cfg.Port is where
	// that daemon is already listening.
	brokerURL := fmt.Sprintf("nats://%s:%d", cfg.Host, cfg.Port)
	conn, err := natsgo.Connect(brokerURL)
	if err != nil {
		return fmt.Errorf("connect to local jsyncd at %s: %w", brokerURL, err)
	}
	defer conn.Close()

	js, err := jetstream.New(conn)
	if err != nil {
		return fmt.Errorf("init jetstream: %w", err)
	}

	maxAttempts := *retries + 1
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := shareAttempt(conn, js, cfg, id, srcPath, targetMachineID, destPath, *encrypt, *timeout, *transferTimeout)
		if err == nil {
			return nil
		}

		var fatal *fatalShareError
		if errors.As(err, &fatal) {
			return fatal.err
		}

		lastErr = err
		if attempt < maxAttempts {
			fmt.Printf("attempt %d/%d failed: %v — retrying in %s\n", attempt, maxAttempts, err, *retryWait)
			time.Sleep(*retryWait)
		}
	}
	return fmt.Errorf("gave up after %d attempt(s): %w", maxAttempts, lastErr)
}

// shareAttempt runs one full handshake-through-completion cycle of `share`.
// A non-nil error is either a *fatalShareError (cmdShare's retry loop must
// stop immediately — a policy rejection or a deterministic local failure,
// retrying changes nothing) or a plain error (worth retrying — a transport
// failure, the daemon reporting the transfer didn't finish, or timing out
// waiting to hear back, all of which a network blip or a momentarily busy
// peer can plausibly cause). Every attempt is a fresh handshake — never a
// reused SessionID — but if the destination has a parked sandbox from an
// earlier attempt against this same peer+destPath (Fase 2 network
// recovery), the daemon reports it via resp.ResumedFiles regardless of
// which attempt asks, so a retry here automatically skips what's already
// there without any extra bookkeeping in this function.
func shareAttempt(conn *natsgo.Conn, js jetstream.JetStream, cfg *config.Config, id *identity.Identity, srcPath, targetMachineID, destPath string, encrypt bool, timeout, transferTimeout time.Duration) error {
	resp, err := fsnats.RequestHandshake(conn, id, targetMachineID, destPath, handshake.DirectionUnidirectional, false, timeout)
	if err != nil {
		return fmt.Errorf("handshake with %s: %w", targetMachineID, err)
	}
	if !resp.Approved {
		return &fatalShareError{fmt.Errorf("handshake rejected by %s: %s", targetMachineID, resp.Reason)}
	}
	if !resp.VerifyBundle() {
		return &fatalShareError{fmt.Errorf("handshake approved but %s's prekey bundle failed to verify — refusing to continue", targetMachineID)}
	}

	fmt.Println("handshake approved, session_id:", resp.SessionID)

	// Subscribe to the completion status before publishing a single byte —
	// the daemon could in principle finish before we'd get around to
	// subscribing afterward, and NATS core pub/sub drops messages nobody
	// was listening for yet. Buffered well past 1: the daemon now
	// publishes periodic progress pings, not just one terminal message
	// (Fase 2 progress reporting), and a buffer of 1 risks blocking the
	// NATS subscription callback if this goroutine doesn't drain
	// immediately.
	statusCh := make(chan daemon.Status, 16)
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
	if encrypt {
		enc, err = buildEncryption(cfg, id, resp.Bundle)
		if err != nil {
			return &fatalShareError{fmt.Errorf("set up encryption: %w", err)}
		}
		fmt.Println("encryption: on (X3DH + Double Ratchet)")
	}

	var skip map[string]string
	if len(resp.ResumedFiles) > 0 {
		skip = make(map[string]string, len(resp.ResumedFiles))
		for _, rf := range resp.ResumedFiles {
			skip[rf.RelPath] = rf.ContentHash
		}
		fmt.Printf("resuming: %s already has %d file(s) from a previous attempt, skipping any that haven't changed\n", targetMachineID, len(skip))
	}

	// Fase 2's share had no exclusion at all before this — it walked and
	// sent everything, including a config.yaml/identity.json/prekeys.json
	// that happened to live inside srcPath. Same matcher watch already
	// applies: DefaultPatterns (now including .jsync/, see
	// internal/ignore) plus any .jsyncignore at srcPath's root.
	matcher, err := ignore.Load(srcPath)
	if err != nil {
		return fmt.Errorf("load %s: %w", ignore.FileName, err)
	}

	totalBytes, err := pipeline.EstimateSendSize(srcPath, skip, matcher)
	if err != nil {
		return fmt.Errorf("estimate size of %s: %w", srcPath, err)
	}

	ar := pipeline.NewArchiveReader(srcPath, skip, matcher)
	defer ar.Close()

	pubCtx, cancel := context.WithTimeout(context.Background(), transferTimeout)
	defer cancel()
	if err := pipeline.PublishArchive(pubCtx, js, fsnats.StreamSubject(resp.SessionID), ar, pipeline.DefaultChunkSize, enc, totalBytes); err != nil {
		return fmt.Errorf("send %s: %w", srcPath, err)
	}
	fmt.Println("all chunks sent, waiting for", targetMachineID, "to finish writing")

	// A progress ping proves the transfer is still alive, so it resets
	// this deadline instead of letting it run out from the moment the
	// last byte was sent — a large-but-healthy transfer that legitimately
	// takes longer than transferTimeout to fully extract and commit no
	// longer times out spuriously partway through. Only silence (nothing
	// at all, not even a progress ping, for transferTimeout) is treated
	// as stalled.
	timer := time.NewTimer(transferTimeout)
	defer timer.Stop()
	printedProgress := false
	for {
		select {
		case st := <-statusCh:
			if !st.Final {
				fmt.Print(progress.Line(st.BytesReceived, st.TotalBytes))
				printedProgress = true
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(transferTimeout)
				continue
			}
			if printedProgress {
				fmt.Println()
			}
			if !st.Completed {
				return fmt.Errorf("%s failed to write %s: %s", targetMachineID, destPath, st.Error)
			}
			fmt.Printf("done: %s -> %s:%s\n", srcPath, targetMachineID, destPath)
			return nil
		case <-timer.C:
			if printedProgress {
				fmt.Println()
			}
			return fmt.Errorf("timed out after %s waiting for %s to confirm the write", transferTimeout, targetMachineID)
		}
	}
}

// watchBootstrapTimeout bounds how long the initiator waits for the
// responder's OpBootstrapAck (encrypt.go) during an encrypted watch
// session's setup — see internal/daemon's bootstrapTimeout for the same
// bound on the other side of this exchange.
const watchBootstrapTimeout = 15 * time.Second

// cmdWatch runs a live, bidirectional Fase 5 sync session: it handshakes
// with DirectionBidirectional (jsyncd's OnApproved starts a matching
// Watcher on its own side, see cmd/jsyncd), runs Fase 5 §1's initial
// reconciliation against the peer (syncfs.Reconcile) so anything either
// side changed while disconnected converges before anything else happens,
// then watches localPath and both publishes its own changes and applies
// the peer's, until interrupted (Ctrl+C / SIGTERM). With --encrypt, every
// event — reconciliation's included — is end-to-end encrypted via Fase 3's
// X3DH + Double Ratchet before any of that starts — see
// buildWatchEncryption.
func cmdWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to the jsync config file (default: ./jsync.yaml or ~/.config/jsync/config.yaml)")
	timeout := fs.Duration("timeout", 10*time.Second, "handshake timeout")
	encrypt := fs.Bool("encrypt", false, "end-to-end encrypt the session (Fase 3: X3DH + Double Ratchet, event contents unreadable to the NATS broker)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 2 {
		return fmt.Errorf("usage: jsync watch [--config path] <local-path> <target-machine-id>:<dest-path>")
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
		return fmt.Errorf("connect to local jsyncd at %s: %w", brokerURL, err)
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

	var lg *auditlog.Logger
	if cfg.AuditLog {
		lg, err = auditlog.Open(cfg.AuditLogDir, localPath, resp.SessionID)
		if err != nil {
			return fmt.Errorf("open audit log: %w", err)
		}
		defer lg.Close()
	}

	echo := syncfs.NewEchoGuard()
	versions := syncfs.NewVersionStore()

	onConflict := func(ev syncfs.Event, conflictPath string) {
		fmt.Fprintf(os.Stderr, "jsync watch: conflict on %s, wrote %s — resolve manually\n", ev.RelPath, conflictPath)
	}

	// Fase 5 §1: converge with whatever targetMachineID's side already has
	// before either side's live Watcher starts — otherwise changes made
	// while disconnected (or a first sync between two non-empty
	// directories) would never propagate, only changes from this point on.
	fmt.Println("reconciling with", targetMachineID+"...")
	if err := syncfs.Reconcile(ctx, js, cons, subject, id.MachineID, targetMachineID, localPath, matcher, versions, echo, onConflict, enc, lg); err != nil {
		return fmt.Errorf("initial reconciliation with %s: %w", targetMachineID, err)
	}

	fw := watch.NewFileWatcher(watch.DefaultDebounce, watch.DefaultBufferSize, matcher)
	changes, watchErrs := fw.Watch(ctx, localPath)
	defer fw.Close()
	go func() {
		for werr := range watchErrs {
			fmt.Fprintln(os.Stderr, "jsync watch: local watch error:", werr)
		}
	}()

	errCh := make(chan error, 2)
	go func() {
		errCh <- syncfs.PublishChanges(ctx, js, subject, id.MachineID, localPath, changes, echo, versions, enc, lg)
	}()
	go func() {
		errCh <- syncfs.ReceiveChanges(ctx, cons, id.MachineID, localPath, echo, versions, onConflict, enc, lg)
	}()

	fmt.Printf("watching %s <-> %s:%s (Ctrl+C to stop)\n", localPath, targetMachineID, destPath)

	select {
	case <-ctx.Done():
		fmt.Println("jsync watch: stopping")
		return nil
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return fmt.Errorf("watch session ended: %w", err)
		}
		return nil
	}
}

// cmdLog prints this node's Fase 6 operation log (internal/auditlog): the
// mirrored file mutations a `watch` session applied locally (dir "in") or
// published to the peer (dir "out"), and what this node decided for each
// (applied / conflict / stale / …). It reads the local log files directly —
// no daemon or NATS connection needed — since the log lives next to
// whichever node did the mirroring.
func cmdLog(args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to the jsync config file (default: ./jsync.yaml or ~/.config/jsync/config.yaml)")
	session := fs.String("session", "", "only show operations from this session id")
	pathSub := fs.String("path", "", "only show operations whose path contains this substring")
	since := fs.String("since", "", "only show operations at or after this time (RFC3339, '2006-01-02', or '2006-01-02 15:04:05')")
	asJSON := fs.Bool("json", false, "emit the raw JSONL records instead of a table")
	listFiles := fs.Bool("files", false, "list the audit log files and the roots they cover, then exit")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resolved, _ := config.Resolve(*cfgPath)
	cfg, err := config.Load(resolved)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	dir := cfg.AuditLogDir

	if *listFiles {
		roots, err := auditlog.Roots(dir)
		if err != nil {
			return fmt.Errorf("read audit log dir: %w", err)
		}
		if len(roots) == 0 {
			fmt.Println("no audit logs under", dir)
			return nil
		}
		for key, root := range roots {
			fmt.Printf("%s.jsonl\t%s\n", key, root)
		}
		return nil
	}

	var sinceT time.Time
	if *since != "" {
		sinceT, err = parseSince(*since)
		if err != nil {
			return err
		}
	}

	root := ""
	switch rest := fs.Args(); len(rest) {
	case 0:
	case 1:
		root = rest[0]
	default:
		return fmt.Errorf("usage: jsync log [flags] [root]")
	}

	recs, err := auditlog.List(dir, auditlog.Query{Root: root, Session: *session, Path: *pathSub, Since: sinceT})
	if err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}
	if len(recs) == 0 {
		fmt.Println("no operations logged")
		return nil
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, r := range recs {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	}

	for _, r := range recs {
		path := r.RelPath
		if r.Op == "rename" {
			path = r.OldRelPath + " -> " + r.RelPath
		}
		line := fmt.Sprintf("%s  %-3s  %-7s  %-13s  %s",
			r.Time.Local().Format("2006-01-02 15:04:05"), r.Dir, r.Op, r.Outcome, path)
		switch {
		case r.ConflictPath != "":
			line += "  (" + r.ConflictPath + ")"
		case r.Detail != "":
			line += "  (" + r.Detail + ")"
		}
		fmt.Println(line)
	}
	return nil
}

// parseSince accepts a few progressively looser timestamp layouts for
// `jsync log --since`, all interpreted in local time.
func parseSince(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse --since %q (want RFC3339, '2006-01-02', or '2006-01-02 15:04:05')", s)
}
