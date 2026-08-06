// Command fileshare is the CLI client: a short-lived process that talks to
// the local or remote fileshared node over NATS to trigger one-off
// operations (share, pull, watch, resolve, keys) — it does not itself keep
// any long-running state, that belongs to the daemon (Fase 4).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	natsgo "github.com/nats-io/nats.go"

	"filesharer/internal/config"
	"filesharer/internal/identity"
	fsnats "filesharer/internal/transport/nats"
)

type subcommand struct {
	name  string
	usage string
	run   func(args []string) error
}

var subcommands = []subcommand{
	{"share", "fileshare share [--config path] <local-path> <target-machine-id>:<dest-path>", cmdShare},
	{"pull", "fileshare pull <target-machine-id>:<path> <dest>", blockedOnPhase("Fase 2 (motor de streaming)")},
	{"watch", "fileshare watch <path> <target-machine-id>:<dest-path>", blockedOnPhase("Fase 5 (watcher)")},
	{"resolve", "fileshare resolve <conflict-file>", blockedOnPhase("Fase 5 (watcher)")},
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

func cmdShare(args []string) error {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.yaml", "path to daemon config file")
	timeout := fs.Duration("timeout", 10*time.Second, "handshake timeout")
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

	resp, err := fsnats.RequestHandshake(conn, id, targetMachineID, *timeout)
	if err != nil {
		return fmt.Errorf("handshake with %s: %w", targetMachineID, err)
	}
	if !resp.Approved {
		return fmt.Errorf("handshake rejected by %s: %s", targetMachineID, resp.Reason)
	}
	if !resp.VerifyBundle() {
		return fmt.Errorf("handshake approved but %s's prekey bundle failed to verify — refusing to continue", targetMachineID)
	}

	fmt.Println("handshake approved")
	fmt.Println("  session_id:", resp.SessionID)
	fmt.Println("  allowed_dest_path:", resp.Params.AllowedDestPath)
	fmt.Printf("streaming %s -> %s:%s is not implemented yet (needs Fase 2) — the secure session is established but no bytes move\n", srcPath, targetMachineID, destPath)
	return nil
}
