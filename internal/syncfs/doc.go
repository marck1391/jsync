// Package syncfs is the Fase 5 reactive sync engine sitting on top of
// internal/watch: the event protocol (CREATE/WRITE/REMOVE/RENAME + content
// hash), echo-loop suppression by comparing content hashes instead of
// counting events, conflict detection via per-file version vectors
// (genuine concurrent edits are marked as *.conflict-<machine_id>-<ts>
// files and surfaced to the user, never silently merged), and the
// hash(RelPath)-partitioned JetStream consumer lanes that keep per-file
// ordering without serializing the whole tree behind one consumer.
package syncfs
