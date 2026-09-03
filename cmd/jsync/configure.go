package main

import (
	"encoding/base64"
	"flag"
	"fmt"

	"github.com/charmbracelet/huh"

	"github.com/marck1391/jsync/internal/config"
	"github.com/marck1391/jsync/internal/wizard"
)

// cmdConfigure is the guided first-run: an interactive REPL (charm/huh) that
// writes jsync.yaml, materialises this node's Ed25519 identity + X3DH
// prekeys, registers the directories to expose (as allowed_dest_paths), and
// optionally launches `jsync watch` right away for a single directory. It is
// a thin wrapper around internal/wizard — `jsyncd install` runs the same
// wizard before registering the service.
func cmdConfigure(args []string) error {
	fs := flag.NewFlagSet("configure", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "path to write the jsync config file to (default: ./jsync.yaml)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// `jsync configure` prepares *this* directory, so it prefers a
	// ./jsync.yaml in the working directory over the XDG home — the opposite
	// bias from `jsyncd install`, whose service has no meaningful cwd.
	def := *cfgPath
	if def == "" {
		if resolved, found := config.Resolve(""); found {
			def = resolved
		} else {
			def = "jsync.yaml"
		}
	}

	res, err := wizard.Run(def)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("wrote:", res.ConfigPath)
	fmt.Println("machine_id:", res.MachineID)
	fmt.Println("public_key:", base64.StdEncoding.EncodeToString(res.PublicKey))
	fmt.Println()
	fmt.Println("Next: hand that public_key to each peer, and run")
	fmt.Println("  jsync keys authorize <their-public-key>")
	fmt.Println("on this node once they hand you theirs.")

	watchable := watchableDirs(res.Dirs)
	if len(watchable) == 0 {
		return nil
	}

	if len(watchable) == 1 {
		start := false
		if err := huh.NewForm(huh.NewGroup(
			huh.NewConfirm().
				Title("Start `jsync watch` now for " + watchable[0].LocalPath + "?").
				Description("Runs in the foreground until Ctrl+C. jsyncd must be running.").
				Value(&start),
		)).Run(); err != nil {
			return err
		}
		if start {
			return cmdWatch([]string{"--config", res.ConfigPath, watchable[0].LocalPath, watchable[0].Target})
		}
	}

	fmt.Println()
	fmt.Println("To start live sync (jsyncd must be running):")
	for _, line := range wizard.WatchCommands(res.ConfigPath, res.Dirs) {
		fmt.Println("  " + line)
	}
	return nil
}

// watchableDirs is the subset of dirs with a sync target set.
func watchableDirs(dirs []wizard.Dir) []wizard.Dir {
	var out []wizard.Dir
	for _, d := range dirs {
		if d.Target != "" {
			out = append(out, d)
		}
	}
	return out
}
