// Command fileshare is the CLI client: a short-lived process that talks to
// the local or remote fileshared node over NATS to trigger one-off
// operations (share, pull, watch, resolve, keys) — it does not itself keep
// any long-running state, that belongs to the daemon (Fase 4).
package main

import (
	"fmt"
	"os"
)

type subcommand struct {
	name  string
	usage string
	run   func(args []string) error
}

var subcommands = []subcommand{
	{"share", "fileshare share <path> <target-machine-id>:<dest-path>", notImplemented},
	{"pull", "fileshare pull <target-machine-id>:<path> <dest>", notImplemented},
	{"watch", "fileshare watch <path> <target-machine-id>:<dest-path>", notImplemented},
	{"resolve", "fileshare resolve <conflict-file>", notImplemented},
	{"keys", "fileshare keys [generate|show|authorize <pubkey>]", notImplemented},
}

func notImplemented(args []string) error {
	return fmt.Errorf("not yet wired up")
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
