package syncfs

import "sync"

// removedSentinel marks a path as "removed locally due to a network event"
// in EchoGuard's entries map — distinguishable from any real content hash
// since ContentHash never produces this value (it's not hex).
const removedSentinel = "removed"

// EchoGuard is the other half of Fase 5's echo-loop guard (event.go's
// Apply is the first half — see its doc comment on why it never triggers a
// local rename). Every time this node applies an incoming Event to its own
// filesystem, it records what it just did here; when this node's own
// Watcher then reports that exact change a moment later, PublishChanges
// recognizes it as its own echo and drops it instead of re-publishing —
// comparing content hashes (or, for a remove, just the fact of removal),
// not counting events, so it isn't fooled by editors that write via a
// different sequence of syscalls than expected (see Fase 5 for why the
// original "ignore the next event" design was rejected).
//
// Safe for concurrent use. Each entry is consumed (deleted) the first time
// it matches — a second local change to the same path that happens to hash
// identically is vanishingly unlikely and, if it ever happened, the safer
// failure mode is to propagate it rather than silently drop a genuine
// edit.
type EchoGuard struct {
	mu      sync.Mutex
	entries map[string]string // relPath -> expected content hash, or removedSentinel
}

// NewEchoGuard returns an empty guard.
func NewEchoGuard() *EchoGuard {
	return &EchoGuard{entries: map[string]string{}}
}

// MarkApplied records that relPath was just written locally (via Apply)
// with content hashing to hash, because of an incoming OpWrite Event.
func (g *EchoGuard) MarkApplied(relPath, hash string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.entries[relPath] = hash
}

// MarkRemoved records that relPath was just removed locally (via Apply)
// because of an incoming OpRemove Event.
func (g *EchoGuard) MarkRemoved(relPath string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.entries[relPath] = removedSentinel
}

// IsEcho reports whether a locally observed write at relPath with the
// given content hash matches what MarkApplied most recently recorded for
// it, consuming the entry if so.
func (g *EchoGuard) IsEcho(relPath, hash string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	want, ok := g.entries[relPath]
	if !ok || want != hash {
		return false
	}
	delete(g.entries, relPath)
	return true
}

// IsEchoRemove reports whether a locally observed removal at relPath
// matches a MarkRemoved recorded for it, consuming the entry if so.
func (g *EchoGuard) IsEchoRemove(relPath string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	want, ok := g.entries[relPath]
	if !ok || want != removedSentinel {
		return false
	}
	delete(g.entries, relPath)
	return true
}
