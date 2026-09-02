// Package auditlog is a forward-only, append-only record of the filesystem
// mutations a Fase 5 Watcher session applied locally (Dir "in") or
// published to the peer (Dir "out"). It is deliberately NOT a
// write-ahead/undo log: it stores no before-images and offers no revert —
// recovering old content is left to whatever version control the user runs
// over the synced tree (see planv1/Fase 6). What it adds over replaying the
// JetStream events stream directly is (a) this node's own decision for each
// event — applied / conflict / stale — which the stream never carries, and
// (b) durability past the events stream's MaxAge, in a plain JSONL file
// that reads with `cat` and needs no running NATS server.
//
// One file per synced root, keyed by a hash of the root's absolute path, so
// successive sessions against the same root append to the same log. The
// op_id is the JetStream stream sequence of the event, so a line here
// correlates back to the events stream while that message still exists.
package auditlog
