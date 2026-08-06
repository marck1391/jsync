// Package watch is the native, per-platform recursive filesystem watcher
// backing Fase 5. Ported from the indexer project's internal/watch (proven
// on Windows via a hand-rolled ReadDirectoryChangesW backend with explicit
// kernel-overflow detection, and on Linux/macOS via github.com/rjeczalik/
// notify's recursive mode) rather than fsnotify, which lacks a public
// recursive-watch API on Windows.
//
// One deliberate divergence from the indexer version: indexer collapses a
// native rename into a plain remove+create pair because it only needs to
// know something changed. This package preserves the OS-native old-path/
// new-path correlation as its own event kind instead, so a directory rename
// can be mirrored on the remote side with a single os.Rename instead of
// re-transferring every file underneath it (see Fase 5).
package watch
