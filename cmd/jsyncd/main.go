// Command jsyncd is the always-running node process (Fase 4): it
// bootstraps the NATS connection in either hub or peer role (Fase 1),
// answers handshake requests, consumes JetStream transfers, and runs the
// Fase 5 filesystem watcher for any configured sync roots.
//
// Invocation forms:
//
//	jsyncd [--config path]     run in the foreground (Ctrl+C / SIGTERM to stop)
//	jsyncd install [--config]  interactive setup, then register as a system service
//	jsyncd uninstall           remove the system service
//	jsyncd start|stop|restart  control the installed service
//	jsyncd status              print the installed service's state
//
// When the OS service manager launches jsyncd, service.Interactive() is
// false and control is handed to service.Run (which calls program.Start).
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kardianos/service"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/marck1391/jsync/internal/config"
	"github.com/marck1391/jsync/internal/crypto/x3dh"
	"github.com/marck1391/jsync/internal/daemon"
	"github.com/marck1391/jsync/internal/handshake"
	"github.com/marck1391/jsync/internal/identity"
	"github.com/marck1391/jsync/internal/pipeline"
	fsnats "github.com/marck1391/jsync/internal/transport/nats"
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

// serviceName is what `jsyncd install` registers with the OS service
// manager (systemd unit name / Windows service name / launchd label).
const serviceName = "jsyncd"

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "jsyncd:", err)
		os.Exit(1)
	}
}

const usageText = `usage:
  jsyncd [--config <path>]        run in the foreground (SIGINT/SIGTERM drains gracefully)
  jsyncd install [--config path]  interactive setup, then register as a system service
  jsyncd uninstall                remove the system service
  jsyncd start | stop | restart   control the installed service
  jsyncd status                   print the installed service's state
`

// dispatch routes a leading verb (install / uninstall / start / stop /
// restart / status) to service management, and everything else — a bare
// `jsyncd` or `jsyncd --config path` — to running the daemon: in the
// foreground when interactive, or under service.Run when the OS service
// manager started us.
func dispatch(args []string) error {
	verb := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		verb, args = args[0], args[1:]
	}
	if verb == "help" || verb == "-h" || verb == "--help" || verb == "-help" {
		fmt.Print(usageText)
		return nil
	}

	switch verb {
	case "install", "uninstall", "start", "stop", "restart", "status":
		svc, svcCfg, err := newService("")
		if err != nil {
			return err
		}
		switch verb {
		case "install":
			return cmdInstall(svc, svcCfg, args)
		case "status":
			return reportStatus(svc)
		default:
			return controlAndReport(svc, verb)
		}
	case "":
		// fall through to running the daemon
	default:
		return fmt.Errorf("unknown command %q\n%s", verb, usageText)
	}

	// The run path: parse --config properly — a bad flag or -h/--help stops
	// here, the way the old top-level flag.Parse (ExitOnError) did.
	fs := flag.NewFlagSet("jsyncd", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
	cfgPath := fs.String("config", "", "path to the jsync config file")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}

	svc, _, err := newService(*cfgPath)
	if err != nil {
		return err
	}

	// Started by the OS service manager: hand the process to service.Run,
	// which calls program.Start and blocks until program.Stop returns.
	if !service.Interactive() {
		return svc.Run()
	}

	// Plain foreground run — unchanged Fase 4 behaviour.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, *cfgPath)
}

// newService builds the kardianos service handle plus its config. cfgPath
// goes into program (used when the service manager calls program.Start) and,
// when non-empty, into the service's own launch arguments.
func newService(cfgPath string) (service.Service, *service.Config, error) {
	svcCfg := serviceConfig(cfgPath)
	svc, err := service.New(&program{cfgPath: cfgPath}, svcCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("service init: %w", err)
	}
	return svc, svcCfg, nil
}

// serviceConfig is the OS-service registration. Arguments/Executable are
// filled in by cmdInstall once the wizard has settled on a config path;
// for the control verbs the already-installed registration is what counts.
func serviceConfig(cfgPath string) *service.Config {
	c := &service.Config{
		Name:        serviceName,
		DisplayName: "jsync daemon",
		Description: "jsync always-on sync/transfer node (jsyncd)",
	}
	if cfgPath != "" {
		c.Arguments = []string{"--config", cfgPath}
	}
	return c
}

// program adapts run() to service.Interface: Start must not block, so the
// daemon runs on its own goroutine under a context that Stop cancels.
type program struct {
	cfgPath string
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
}

func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})
	go func() {
		defer close(p.done)
		p.err = run(ctx, p.cfgPath)
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.done != nil {
		select {
		case <-p.done:
		case <-time.After(drainTimeout + 2*time.Second):
		}
	}
	return p.err
}

// run is the daemon proper. ctx cancellation (a signal in the foreground, a
// service Stop under a manager) triggers the ordered shutdown.
func run(ctx context.Context, cfgPath string) error {
	resolved, _ := config.Resolve(cfgPath)
	cfg, err := config.Load(resolved)
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

	resumes := daemon.NewResumeRegistry()

	responder := &handshake.Responder{
		Authorized: authorized,
		Sessions:   handshake.NewSessionStore(),
		Prekeys:    prekeys,
		Guard:      handshake.NewReplayGuard(),
		DefaultParams: handshake.Params{
			MaxPayloadBytes:  cfg.MaxPayloadBytes,
			AllowedDestPaths: []string(cfg.AllowedDestPaths),
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
	auditLogDir := ""
	if cfg.AuditLog {
		auditLogDir = cfg.AuditLogDir
	}

	responder.OnApproved = func(sess *handshake.Session) {
		if sess.Params.Direction == handshake.DirectionBidirectional {
			go func() {
				if err := daemon.WatchSession(ctx, node.Conn, js, sess, id.MachineID, prekeys, id.PublicKey, auditLogDir); err != nil {
					fmt.Fprintf(os.Stderr, "jsyncd: watch session %s: %v\n", sess.ID, err)
				}
			}()
			return
		}

		if _, err := fsnats.EnsureStream(ctx, js, sess.ID); err != nil {
			fmt.Fprintf(os.Stderr, "jsyncd: ensure stream for session %s: %v\n", sess.ID, err)
			return
		}
		go func() {
			if err := daemon.ReceiveSession(ctx, node.Conn, js, sess, prekeys, id.PublicKey, resumes); err != nil {
				fmt.Fprintf(os.Stderr, "jsyncd: receive session %s: %v\n", sess.ID, err)
			}
		}()
	}

	sub, err := fsnats.ServeHandshake(node.Conn, id.MachineID, responder)
	if err != nil {
		node.Close()
		return fmt.Errorf("serve handshake: %w", err)
	}

	fmt.Println("jsyncd: ready")
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
				fmt.Fprintln(os.Stderr, "jsyncd: save prekeys:", err)
			}
		case <-watchdogTicker.C:
			responder.Sessions.Sweep()
			for _, sandboxDir := range resumes.Sweep(time.Now()) {
				if err := pipeline.AbortSandbox(sandboxDir); err != nil {
					fmt.Fprintln(os.Stderr, "jsyncd: sweep abandoned resume sandbox:", err)
				}
			}
		}
	}

	fmt.Println("jsyncd: shutting down")
	_ = sub.Unsubscribe()
	if err := prekeys.Save(cfg.PrekeysPath); err != nil {
		fmt.Fprintln(os.Stderr, "jsyncd: save prekeys on shutdown:", err)
	}
	if err := node.Drain(drainTimeout); err != nil {
		fmt.Fprintln(os.Stderr, "jsyncd: drain:", err)
	}
	return nil
}
