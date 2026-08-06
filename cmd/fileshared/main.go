// Command fileshared is the always-running node process (Fase 4): it
// bootstraps the NATS connection in either hub or peer role (Fase 1),
// answers handshake requests, consumes JetStream transfers, and runs the
// Fase 5 filesystem watcher for any configured sync roots.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to daemon config file")
	flag.Parse()

	fmt.Fprintf(os.Stdout, "fileshared: scaffold only — config=%s\n", *cfgPath)
	fmt.Fprintln(os.Stdout, "not yet wired: config load, NATS hub/peer bootstrap, handshake responder, stream consumer, watcher")
}
