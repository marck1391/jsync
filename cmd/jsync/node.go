package main

import (
	"flag"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/marck1391/jsync/internal/config"
	"github.com/marck1391/jsync/internal/yamledit"
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
// collide with path syntax. The rule lives in internal/config so
// `jsync configure` / `jsyncd install` apply the same one.
func validAlias(alias string) error { return config.ValidNodeAlias(alias) }

// editNodes sets or removes one entry in the `nodes:` mapping of cfgFile and
// writes it back atomically. A missing file/key is created; removing the
// last entry drops the `nodes:` key entirely.
func editNodes(cfgFile, alias, machineID string, remove bool) (bool, error) {
	doc, err := yamledit.Load(cfgFile)
	if err != nil {
		return false, err
	}

	root := yamledit.DocumentRoot(&doc)
	nodes := yamledit.Get(root, "nodes")
	if nodes != nil && nodes.Kind != yaml.MappingNode {
		return false, fmt.Errorf("%s: `nodes` is not a mapping", cfgFile)
	}

	if remove {
		if nodes == nil {
			return false, nil
		}
		if old := yamledit.Delete(nodes, alias); old == nil {
			return false, nil
		}
		if len(nodes.Content) == 0 {
			yamledit.Delete(root, "nodes")
		}
	} else {
		if nodes == nil {
			nodes = yamledit.Mapping()
			yamledit.Set(root, "nodes", nodes)
		}
		if cur := yamledit.Get(nodes, alias); cur != nil && cur.Kind == yaml.ScalarNode && cur.Value == machineID {
			return false, nil
		}
		yamledit.SetString(nodes, alias, machineID)
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
