package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"gopkg.in/yaml.v3"

	"jsync/internal/config"
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
	var doc yaml.Node
	if data, err := os.ReadFile(cfgFile); err == nil {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return false, fmt.Errorf("parse %s: %w", cfgFile, err)
		}
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("read %s: %w", cfgFile, err)
	}

	root := documentRoot(&doc)
	seq := mappingValue(root, "allowed_dest_paths")
	if seq == nil {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		mappingSet(root, "allowed_dest_paths", seq)
	} else if seq.Kind == yaml.ScalarNode {
		// `allowed_dest_paths: /one` — promote to a one-item sequence.
		scalar := *seq
		*seq = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{&scalar}}
	}

	// Fold a legacy singular key in, then delete it.
	if legacy := mappingDelete(root, "allowed_dest_path"); legacy != nil && legacy.Kind == yaml.ScalarNode && legacy.Value != "" {
		seqAppendUnique(seq, legacy.Value)
	}

	changed := false
	if remove {
		kept := seq.Content[:0]
		for _, item := range seq.Content {
			if item.Kind == yaml.ScalarNode && samePath(item.Value, target) {
				changed = true
				continue
			}
			kept = append(kept, item)
		}
		seq.Content = kept
	} else {
		changed = seqAppendUnique(seq, target)
	}

	if !changed {
		return false, nil
	}

	buf, err := marshalNode(&doc)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(cfgFile), 0o755); err != nil {
		return false, fmt.Errorf("create %s: %w", filepath.Dir(cfgFile), err)
	}
	tmp := cfgFile + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return false, fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, cfgFile); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("replace %s: %w", cfgFile, err)
	}
	return true, nil
}

// documentRoot returns doc's top mapping node, initialising an empty
// document (nil Kind) into a fresh mapping.
func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == 0 {
		doc.Kind = yaml.DocumentNode
	}
	if len(doc.Content) == 0 {
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	return doc.Content[0]
}

// mappingValue returns the value node for key in a mapping node, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// mappingSet sets (or replaces) key -> val in a mapping node.
func mappingSet(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
}

// mappingDelete removes key from a mapping node, returning its old value
// node (or nil).
func mappingDelete(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			val := m.Content[i+1]
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return val
		}
	}
	return nil
}

// samePath reports whether a and b denote the same location, ignoring
// trailing slashes and redundant separators (filepath.Clean), without
// otherwise rewriting either string.
func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// seqAppendUnique appends value as a scalar to seq (verbatim — the caller
// decides the canonical form) unless a samePath item is already present;
// returns whether it appended.
func seqAppendUnique(seq *yaml.Node, value string) bool {
	for _, item := range seq.Content {
		if item.Kind == yaml.ScalarNode && samePath(item.Value, value) {
			return false
		}
	}
	seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
	return true
}

func marshalNode(doc *yaml.Node) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encode yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode yaml: %w", err)
	}
	return b.Bytes(), nil
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
