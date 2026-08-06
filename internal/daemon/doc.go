// Package daemon is the always-running node process (Fase 4): the NATS
// message dispatcher, the handshake worker, the disk sandbox/atomic-commit
// worker (.fileshare_tmp_<session_id> -> os.Rename), and the orphaned-session
// watchdog/garbage collector. It owns the process lifecycle that
// internal/watch (Fase 5) plugs into — the watcher is not a separate mode,
// it runs inside this same process.
package daemon
