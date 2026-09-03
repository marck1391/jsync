package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"github.com/marck1391/jsync/internal/config"
	"github.com/marck1391/jsync/internal/yamledit"
)

// cmdAllow edits the `allowed_dest_paths` list in the jsync config file:
// the set of roots a remote peer is permitted to ask this daemon to write
// to (Fase 1 handshake policy). It rewrites the YAML in place with
// yaml.Node so existing comments and key order survive.
//
//	jsync allow <dest-path>            add a root
//	jsync allow --remove <dest-path>   drop a root
//	jsync allow --list                 print the current list
//
// A running jsyncd reads this list once at startup, so a change here needs
// a daemon restart to take effect; cmdAllow says so when it detects one.
func cmdAllow(args []string) error {
	fs := flag.NewFlagSet("allow", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to the jsync config file (default: ./jsync.yaml or ~/.config/jsync/config.yaml)")
	list := fs.Bool("list", false, "print the current allowed_dest_paths and exit")
	remove := fs.Bool("remove", false, "remove the given path instead of adding it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	resolved, _ := config.Resolve(*cfgPath)

	if *list {
		cfg, err := config.Load(resolved)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if len(cfg.AllowedDestPaths) == 0 {
			fmt.Println("allowed_dest_paths is empty — any requested_dest_path is accepted")
			return nil
		}
		fmt.Printf("allowed_dest_paths (from %s):\n", resolved)
		for _, p := range cfg.AllowedDestPaths {
			fmt.Println("  " + p)
		}
		return nil
	}

	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: jsync allow [--config path] <dest-path> | jsync allow --remove <dest-path> | jsync allow --list")
	}
	target, err := filepath.Abs(rest[0])
	if err != nil {
		return fmt.Errorf("resolve %q: %w", rest[0], err)
	}
	target = filepath.Clean(target)

	if !*remove {
		if info, statErr := os.Stat(target); statErr != nil || !info.IsDir() {
			fmt.Fprintf(os.Stderr, "jsync allow: warning: %s does not exist or is not a directory\n", target)
		}
	}

	changed, err := editAllowedDestPaths(resolved, target, *remove)
	if err != nil {
		return err
	}
	switch {
	case !changed && *remove:
		fmt.Printf("%s was not in allowed_dest_paths\n", target)
		return nil
	case !changed:
		fmt.Printf("%s is already in allowed_dest_paths\n", target)
		return nil
	case *remove:
		fmt.Printf("removed %s from allowed_dest_paths in %s\n", target, resolved)
	default:
		fmt.Printf("added %s to allowed_dest_paths in %s\n", target, resolved)
	}

	if daemonReachable(resolved) {
		fmt.Println("a jsyncd is running on this host — restart it for the change to take effect")
	}
	return nil
}

// editAllowedDestPaths applies one add/remove to the allowed_dest_paths
// sequence in cfgFile and writes it back atomically. A missing file is
// created (along with its directory). A pre-existing singular
// `allowed_dest_path` key is folded into the sequence and dropped.
func editAllowedDestPaths(cfgFile, target string, remove bool) (bool, error) {
	doc, err := yamledit.Load(cfgFile)
	if err != nil {
		return false, err
	}

	root := yamledit.DocumentRoot(&doc)
	seq := yamledit.Get(root, "allowed_dest_paths")
	if seq == nil {
		seq = yamledit.Sequence()
		yamledit.Set(root, "allowed_dest_paths", seq)
	} else if seq.Kind == yaml.ScalarNode {
		// `allowed_dest_paths: /one` — promote to a one-item sequence.
		scalar := *seq
		*seq = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{&scalar}}
	}

	// Fold a legacy singular key in, then delete it.
	if legacy := yamledit.Delete(root, "allowed_dest_path"); legacy != nil && legacy.Kind == yaml.ScalarNode && legacy.Value != "" {
		yamledit.AppendUnique(seq, legacy.Value)
	}

	changed := false
	if remove {
		kept := seq.Content[:0]
		for _, item := range seq.Content {
			if item.Kind == yaml.ScalarNode && yamledit.SamePath(item.Value, target) {
				changed = true
				continue
			}
			kept = append(kept, item)
		}
		seq.Content = kept
	} else {
		changed = yamledit.AppendUnique(seq, target)
	}

	if !changed {
		return false, nil
	}

	buf, err := yamledit.Marshal(&doc)
	if err != nil {
		return false, err
	}
	if err := yamledit.AtomicWrite(cfgFile, buf, 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// daemonReachable reports whether a NATS client port is accepting
// connections at the host/port from cfgFile — a cheap "is jsyncd up here?"
// probe.
func daemonReachable(cfgFile string) bool {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return false
	}
	conn, err := natsgo.Connect(
		fmt.Sprintf("nats://%s:%d", cfg.Host, cfg.Port),
		natsgo.Timeout(500*time.Millisecond),
		natsgo.RetryOnFailedConnect(false),
	)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
