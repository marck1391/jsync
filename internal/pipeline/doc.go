// Package pipeline is the Fase 2 streaming engine: the sender side chains
// FS walk -> tar -> gzip -> chunk splitter -> JetStream publish entirely
// through io.Reader/io.Writer (via io.Pipe), never buffering a whole file
// or archive in memory. The receiver side runs the same chain in reverse
// and commits atomically (sandbox dir + os.Rename, Fase 4 §Paso 4).
//
// Fase 3's ratchet-encrypt stage is not wired in yet — when it lands, it
// slots in between gzip and the chunk splitter on the sender side (and
// symmetrically on the receiver side), and the chunk headers defined here
// grow a ratchet-step field alongside Chunk-Sequence/Is-Final-Chunk.
package pipeline
