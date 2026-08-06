// Package progress consumes the fileshare.status.<session_id> subject
// (Fase 2 §5) and exposes transfer progress (chunk count, throughput, ETA)
// for the CLI to render. Kept separate from pipeline so cmd/fileshare can
// depend on it without pulling in the sender/receiver internals.
package progress
