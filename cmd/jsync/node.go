package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"jsync/internal/config"
)

// cmdNode manages the `nodes:` alias map in the jsync config file — friendly
// names for peer machine_ids so `jsync share ./x vm-01:/dest` works instead
// of pasting a raw id. Edits the YAML in place with yaml.Node so comments
// and key order survive. The map is local addressing only: it is never sent
// to anyone and grants no trust (that stays in authorized_clients via
// `jsync keys authorize`).
//
//	jsync node add <alias> <machine-id>
//	jsync node rm  <alias>
//	jsync node ls
func cmdNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to the jsync config file (default: ./jsync.yaml or ~/.config/jsync/config.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: jsync node add <alias> <machine-id> | jsync node rm <alias> | jsync node ls")
	}
	resolved, _ := config.Resolve(*cfgPath)

	switch rest[0] {
	case "ls", "list":
		cfg, err := config.Load(resolved)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if len(cfg.Nodes) == 0 {
			fmt.Println("no node aliases defined")
			return nil
		}
		aliases := make([]string, 0, len(cfg.Nodes))
		for a := range cfg.Nodes {
			aliases = append(aliases, a)
		}
		sort.Strings(aliases)
		fmt.Printf("node aliases (from %s):\n", resolved)
		for _, a := range aliases {
			fmt.Printf("  %-16s %s\n", a, cfg.Nodes[a])
		}
		return nil

	case "add":
		if len(rest) != 3 {
			return fmt.Errorf("usage: jsync node add <alias> <machine-id>")
		}
		alias, machineID := rest[1], rest[2]
		if err := validAlias(alias); err != nil {
			return err
		}
		changed, err := editNodes(resolved, alias, machineID, false)
		if err != nil {
			return err
		}
		if !changed {
			fmt.Printf("%s already maps to %s\n", alias, machineID)
			return nil
		}
		fmt.Printf("%s -> %s  (in %s)\n", alias, machineID, resolved)
		return nil

	case "rm", "remove", "del", "delete":
		if len(rest) != 2 {
			return fmt.Errorf("usage: jsync node rm <alias>")
		}
		changed, err := editNodes(resolved, rest[1], "", true)
		if err != nil {
			return err
		}
		if !changed {
			fmt.Printf("no alias %q to remove\n", rest[1])
			return nil
		}
		fmt.Printf("removed alias %q from %s\n", rest[1], resolved)
		return nil

	default:
		return fmt.Errorf("unknown node subcommand %q (want add, rm, or ls)", rest[0])
	}
}

// validAlias rejects names that would break `<alias>:<dest-path>` parsing or
// collide with path syntax.
func validAlias(alias string) error {
	if alias == "" {
		return fmt.Errorf("alias must not be empty")
	}
	if strings.ContainsAny(alias, ":/\\ \t") {
		return fmt.Errorf("alias %q must not contain ':', '/', '\\' or whitespace", alias)
	}
	return nil
}

// editNodes sets or removes one entry in the `nodes:` mapping of cfgFile and
// writes it back atomically. A missing file/key is created; removing the
// last entry drops the `nodes:` key entirely.
func editNodes(cfgFile, alias, machineID string, remove bool) (bool, error) {
	var doc yaml.Node
	if data, err := os.ReadFile(cfgFile); err == nil {
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return false, fmt.Errorf("parse %s: %w", cfgFile, err)
		}
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("read %s: %w", cfgFile, err)
	}

	root := documentRoot(&doc)
	nodes := mappingValue(root, "nodes")
	if nodes != nil && nodes.Kind != yaml.MappingNode {
		return false, fmt.Errorf("%s: `nodes` is not a mapping", cfgFile)
	}

	if remove {
		if nodes == nil {
			return false, nil
		}
		if old := mappingDelete(nodes, alias); old == nil {
			return false, nil
		}
		if len(nodes.Content) == 0 {
			mappingDelete(root, "nodes")
		}
	} else {
		if nodes == nil {
			nodes = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			mappingSet(root, "nodes", nodes)
		}
		if cur := mappingValue(nodes, alias); cur != nil && cur.Kind == yaml.ScalarNode && cur.Value == machineID {
			return false, nil
		}
		mappingSet(nodes, alias, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: machineID})
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
