// Package pipeline is the Fase 2 streaming engine: the sender side chains
// FS walk -> tar -> gzip -> ratchet-encrypt -> chunk splitter -> JetStream
// publish entirely through io.Reader/io.Writer, never buffering a whole
// file or archive in memory. The receiver side runs the same chain in
// reverse. Chunk headers (sequence, final flag, ratchet step) are defined
// here since both directions need to agree on them.
package pipeline
