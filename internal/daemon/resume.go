package daemon

import (
	"crypto/ed25519"
	"path/filepath"
	"sync"
	"time"

	"jsync/internal/handshake"
)

// resumeGracePeriod is how long a parked sandbox survives without being
// reclaimed before the watchdog sweep deletes it for good (Fase 2
// "recuperación de red" — matches the 5-minute grace period the original
// plan proposed for a network blip, now also covering the sender's process
// dying and a fresh `jsync share` invocation resuming later). Every
// failed attempt that reclaims and re-parks the same transfer refreshes
// this — the clock measures time since the *last* attempt, not since the
// first failure.
const resumeGracePeriod = 5 * time.Minute

// ResumeRegistry tracks sandboxes ReceiveSession has parked instead of
// deleted after a failed Fase 2 transfer, so a later attempt from the same
// peer to the same destination can pick up where the last one left off
// instead of re-sending everything. Pure in-memory bookkeeping, same style
// as handshake.SessionStore — nothing persisted to disk, a daemon restart
// loses the registry (the parked sandboxes themselves are still on disk,
// but become unreachable/orphaned; a future daemon restart could in
// principle rediscover them by scanning for .jsync_tmp_* directories,
// but that's not implemented here).
//
// Keyed by (peer's verified Ed25519 identity, cleaned destPath) — never by
// destPath alone, so one authorized peer can never see or claim another
// peer's parked transfer, matching the trust boundary Responder.Handle
// already establishes before ResumeLookup is ever called.
type ResumeRegistry struct {
	mu      sync.Mutex
	entries map[resumeKey]*resumeEntry
}

type resumeKey struct {
	peerPub  string // ed25519.PublicKey, used as a map key via string conversion
	destPath string
}

type resumeEntry struct {
	sandboxDir string
	completed  map[string]string // relPath -> sha256 hex, only fully-written files
	expiresAt  time.Time
}

// NewResumeRegistry returns an empty registry.
func NewResumeRegistry() *ResumeRegistry {
	return &ResumeRegistry{entries: map[resumeKey]*resumeEntry{}}
}

func newResumeKey(peerPub ed25519.PublicKey, destPath string) resumeKey {
	return resumeKey{peerPub: string(peerPub), destPath: filepath.Clean(destPath)}
}

// Park records sandboxDir as resumable for grace after a failed attempt,
// along with completed — the files ReceiveSession had already fully
// extracted and verified when the failure happened. Overwrites (and
// refreshes the expiry of) any existing entry for the same key, which is
// exactly what should happen when a reclaimed sandbox fails again.
func (r *ResumeRegistry) Park(peerPub ed25519.PublicKey, destPath, sandboxDir string, completed map[string]string, grace time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[newResumeKey(peerPub, destPath)] = &resumeEntry{
		sandboxDir: sandboxDir,
		completed:  completed,
		expiresAt:  time.Now().Add(grace),
	}
}

// Claim removes and returns the parked entry for (peerPub, destPath), if
// any and not expired — the caller becomes responsible for that
// sandboxDir from this point on (reusing it, and re-Park-ing it if this
// attempt fails too). ok is false if there's nothing to resume, in which
// case the caller should start a fresh sandbox.
func (r *ResumeRegistry) Claim(peerPub ed25519.PublicKey, destPath string) (sandboxDir string, completed map[string]string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := newResumeKey(peerPub, destPath)
	entry, found := r.entries[key]
	if !found {
		return "", nil, false
	}
	delete(r.entries, key)
	if time.Now().After(entry.expiresAt) {
		return "", nil, false
	}
	return entry.sandboxDir, entry.completed, true
}

// Peek reports what's parked for (peerPub, destPath) without consuming
// it — used by Responder.ResumeLookup (internal/handshake) to tell the
// requester what it can skip re-sending, before ReceiveSession has even
// started (let alone decided to Claim it). Returns nil if there's nothing
// resumable, including an expired entry (Peek never resurrects one — an
// expired entry stays invisible until the next Sweep actually removes it,
// but is never handed out as if it were still good).
func (r *ResumeRegistry) Peek(peerPub ed25519.PublicKey, destPath string) []handshake.ResumedFile {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, found := r.entries[newResumeKey(peerPub, destPath)]
	if !found || time.Now().After(entry.expiresAt) {
		return nil
	}
	files := make([]handshake.ResumedFile, 0, len(entry.completed))
	for relPath, hash := range entry.completed {
		files = append(files, handshake.ResumedFile{RelPath: relPath, ContentHash: hash})
	}
	return files
}

// Sweep removes every entry whose grace period has passed as of now and
// returns their sandbox directories, so the caller can AbortSandbox each
// one — this registry does no filesystem I/O itself, same separation of
// concerns as the rest of this package's bookkeeping types.
func (r *ResumeRegistry) Sweep(now time.Time) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var expired []string
	for key, entry := range r.entries {
		if now.After(entry.expiresAt) {
			expired = append(expired, entry.sandboxDir)
			delete(r.entries, key)
		}
	}
	return expired
}
