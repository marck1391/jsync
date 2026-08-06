// Command fileshared is the always-running node process (Fase 4): it
// bootstraps the NATS connection in either hub or peer role (Fase 1),
// answers handshake requests, consumes JetStream transfers, and runs the
// Fase 5 filesystem watcher for any configured sync roots.
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"filesharer/internal/config"
	"filesharer/internal/crypto/x3dh"
	"filesharer/internal/daemon"
	"filesharer/internal/handshake"
	"filesharer/internal/identity"
	"filesharer/internal/pipeline"
	fsnats "filesharer/internal/transport/nats"
)

// prekeySaveInterval bounds how long a crash (not a graceful shutdown,
// which always saves) can leave a consumed One-Time PreKey looking
// unconsumed on disk — see Fase 1 "Notas de Implementación" for why this
// matters: replaying a One-Time PreKey after a crash-restart quietly loses
// the property that makes it "one-time".
const prekeySaveInterval = 10 * time.Second

// drainTimeout bounds the graceful shutdown described in Fase 4 "Apagado
// Ordenado".
const drainTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fileshared:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "config.yaml", "path to daemon config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	machineID := cfg.MachineID
	if machineID == "" {
		machineID, err = identity.NewMachineID()
		if err != nil {
			return fmt.Errorf("generate machine id: %w", err)
		}
	}

	id, err := identity.Load(cfg.IdentityPath, machineID)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	authorized, err := identity.LoadAuthorizedClients(cfg.AuthorizedClientsPath)
	if err != nil {
		return fmt.Errorf("load authorized_clients: %w", err)
	}

	prekeys, err := x3dh.LoadStore(cfg.PrekeysPath, id.PublicKey, id.PrivateKey, cfg.OneTimePreKeyCount)
	if err != nil {
		return fmt.Errorf("load prekeys: %w", err)
	}

	role := fsnats.RoleHub
	if cfg.Role == config.RolePeer {
		role = fsnats.RolePeer
	}
	node, err := fsnats.Bootstrap(fsnats.Config{
		Role:              role,
		Host:              cfg.Host,
		Port:              cfg.Port,
		LeafNodePort:      cfg.LeafNodePort,
		HubLeafNodeURL:    cfg.HubLeafNodeURL,
		JetStreamStoreDir: cfg.JetStreamStoreDir,
		Debug:             cfg.Debug,
	})
	if err != nil {
		return fmt.Errorf("bootstrap nats (%s): %w", cfg.Role, err)
	}

	js, err := jetstream.New(node.Conn)
	if err != nil {
		node.Close()
		return fmt.Errorf("init jetstream: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	resumes := daemon.NewResumeRegistry()

	responder := &handshake.Responder{
		Authorized: authorized,
		Sessions:   handshake.NewSessionStore(),
		Prekeys:    prekeys,
		Guard:      handshake.NewReplayGuard(),
		DefaultParams: handshake.Params{
			MaxPayloadBytes: cfg.MaxPayloadBytes,
			AllowedDestPath: cfg.AllowedDestPath,
		},
		ResumeLookup: func(peerPub ed25519.PublicKey, destPath string) []handshake.ResumedFile {
			return resumes.Peek(peerPub, destPath)
		},
	}
	// Handle runs synchronously inside the NATS subscription callback, so
	// OnApproved must not block it on the actual (potentially slow, or for
	// a watch session, unboundedly long-lived) work — hence the goroutines
	// below. Creating the Fase 2 stream itself stays synchronous and runs
	// before Handle's Response goes out, though: the initiator only learns
	// the session was approved once this returns, and if it started
	// publishing chunks before the stream existed, JetStream would have
	// nothing to accept them into. A watch session's events stream doesn't
	// need this same synchronous guarantee — WatchSession creates it
	// itself before the initiator's own Watcher could plausibly publish
	// anything, since the initiator side has its own network round trip
	// (EnsureEventsStream) to do first too.
	responder.OnApproved = func(sess *handshake.Session) {
		if sess.Params.Direction == handshake.DirectionBidirectional {
			go func() {
				if err := daemon.WatchSession(ctx, node.Conn, js, sess, id.MachineID, prekeys, id.PublicKey); err != nil {
					fmt.Fprintf(os.Stderr, "fileshared: watch session %s: %v\n", sess.ID, err)
				}
			}()
			return
		}

		if _, err := fsnats.EnsureStream(ctx, js, sess.ID); err != nil {
			fmt.Fprintf(os.Stderr, "fileshared: ensure stream for session %s: %v\n", sess.ID, err)
			return
		}
		go func() {
			if err := daemon.ReceiveSession(ctx, node.Conn, js, sess, prekeys, id.PublicKey, resumes); err != nil {
				fmt.Fprintf(os.Stderr, "fileshared: receive session %s: %v\n", sess.ID, err)
			}
		}()
	}

	sub, err := fsnats.ServeHandshake(node.Conn, id.MachineID, responder)
	if err != nil {
		node.Close()
		return fmt.Errorf("serve handshake: %w", err)
	}

	fmt.Println("fileshared: ready")
	fmt.Println("  machine_id:", id.MachineID)
	fmt.Println("  role:", cfg.Role)
	fmt.Println("  client_url:", node.ClientURL())
	if cfg.Role == config.RoleHub {
		fmt.Println("  leaf_node_url:", node.LeafNodeURL())
	}

	saveTicker := time.NewTicker(prekeySaveInterval)
	defer saveTicker.Stop()
	watchdogTicker := time.NewTicker(1 * time.Minute)
	defer watchdogTicker.Stop()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-saveTicker.C:
			if err := prekeys.Save(cfg.PrekeysPath); err != nil {
				fmt.Fprintln(os.Stderr, "fileshared: save prekeys:", err)
			}
		case <-watchdogTicker.C:
			responder.Sessions.Sweep()
			for _, sandboxDir := range resumes.Sweep(time.Now()) {
				if err := pipeline.AbortSandbox(sandboxDir); err != nil {
					fmt.Fprintln(os.Stderr, "fileshared: sweep abandoned resume sandbox:", err)
				}
			}
		}
	}

	fmt.Println("fileshared: shutting down")
	_ = sub.Unsubscribe()
	if err := prekeys.Save(cfg.PrekeysPath); err != nil {
		fmt.Fprintln(os.Stderr, "fileshared: save prekeys on shutdown:", err)
	}
	if err := node.Drain(drainTimeout); err != nil {
		fmt.Fprintln(os.Stderr, "fileshared: drain:", err)
	}
	return nil
}
