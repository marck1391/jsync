package auditlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DefaultMaxBytes is the size a log file may reach before Log rotates it,
// shifting "<name>" -> "<name>.1" -> ... -> "<name>.<maxBackups>" and
// dropping whatever falls off the end. This is an audit trail, not an
// archive: the ceiling per root is (maxBackups+1)*DefaultMaxBytes and the
// oldest history beyond that is discarded. Overridable per Logger via
// SetMaxBytes, mainly for tests.
const DefaultMaxBytes = 8 << 20

// maxBackups is how many rotated generations are kept alongside the live
// file. Rotations happen once per DefaultMaxBytes written, so the O(n)
// renames here are rare.
const maxBackups = 4

// Record is one line of the log. Only the fields relevant to Op are set:
// ContentHash/Bytes ride OpWrite, OldRelPath rides OpRename, ConflictPath
// is set only when Outcome is "conflict", Detail carries error text.
type Record struct {
	// OpID is the JetStream stream sequence of the underlying event — a
	// stable handle back to the events stream while that message still
	// exists (it is only monotonic within a single session's stream). 0
	// for records that have no backing message (a dropped rescan).
	OpID uint64 `json:"op_id"`

	Time    time.Time `json:"ts"`
	Session string    `json:"session,omitempty"`

	// Dir is "in" for a mutation this node applied from the peer, "out"
	// for one it published to the peer.
	Dir string `json:"dir"`

	// Origin is the publishing node's machine_id (== this node's own for
	// Dir "out").
	Origin string `json:"origin,omitempty"`

	Op          string `json:"op"` // write | remove | rename | rescan
	RelPath     string `json:"rel_path,omitempty"`
	OldRelPath  string `json:"old_rel_path,omitempty"`
	ContentHash string `json:"content_hash,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`

	// Outcome is the result: applied | conflict | stale | published |
	// reconciled | error | rescan-dropped.
	Outcome      string `json:"outcome"`
	ConflictPath string `json:"conflict_path,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// Logger appends Records to one root's log file. A nil *Logger is a valid
// no-op sink — the same contract syncfs.Encryption uses for "feature off" —
// so callers thread it unconditionally and only Open one when auditing is
// enabled.
type Logger struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	session  string
	maxBytes int64
	size     int64
	err      error // last write/rotate error; surfaced via Err(), never fatal to a sync session
}

// rootKey is the log filename stem for root: a hash of its cleaned
// absolute path, so the name is bounded and stable across sessions without
// depending on the path being filesystem-safe.
func rootKey(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		abs = root
	}
	sum := sha256.Sum256([]byte(filepath.Clean(abs)))
	return hex.EncodeToString(sum[:])[:16]
}

// Open returns a Logger appending to dir/<rootKey>.jsonl, creating dir if
// needed and writing a dir/<rootKey>.root sidecar (best-effort) so `jsync
// log` can map the hashed filename back to a readable path. session is
// stamped onto every Record that doesn't set its own.
func Open(dir, root, session string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("auditlog: create %s: %w", dir, err)
	}
	key := rootKey(root)

	if abs, err := filepath.Abs(root); err == nil {
		sidecar := filepath.Join(dir, key+".root")
		if _, statErr := os.Stat(sidecar); os.IsNotExist(statErr) {
			_ = os.WriteFile(sidecar, []byte(abs+"\n"), 0o600)
		}
	}

	path := filepath.Join(dir, key+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("auditlog: open %s: %w", path, err)
	}
	var size int64
	if info, statErr := f.Stat(); statErr == nil {
		size = info.Size()
	}
	return &Logger{f: f, path: path, session: session, maxBytes: DefaultMaxBytes, size: size}, nil
}

// SetMaxBytes overrides the rotation threshold (see DefaultMaxBytes).
func (l *Logger) SetMaxBytes(n int64) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.maxBytes = n
	l.mu.Unlock()
}

// Log appends rec. A nil Logger, or a Logger whose file handle was lost to
// an earlier error, drops the record silently: an audit-log write failure
// must never abort the file-sync session it is observing. The error is kept
// for Err().
func (l *Logger) Log(rec Record) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	if rec.Time.IsZero() {
		rec.Time = time.Now().UTC()
	}
	if rec.Session == "" {
		rec.Session = l.session
	}

	line, err := json.Marshal(rec)
	if err != nil {
		l.err = err
		return
	}
	line = append(line, '\n')

	if l.maxBytes > 0 && l.size > 0 && l.size+int64(len(line)) > l.maxBytes {
		l.rotate()
		if l.f == nil {
			return
		}
	}

	n, err := l.f.Write(line)
	l.size += int64(n)
	if err != nil {
		l.err = err
	}
}

// rotate is called with l.mu held: close the current file, shift the
// rotated generations down one (dropping the oldest), move the live file to
// "<path>.1", and reopen a fresh one. On failure l.f is left nil and
// subsequent Log calls drop until the process restarts — deliberately not
// retried in a hot path.
func (l *Logger) rotate() {
	_ = l.f.Close()
	l.f = nil

	_ = os.Remove(fmt.Sprintf("%s.%d", l.path, maxBackups))
	for n := maxBackups - 1; n >= 1; n-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.path, n), fmt.Sprintf("%s.%d", l.path, n+1))
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		l.err = err
		return
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		l.err = err
		return
	}
	l.f = f
	l.size = 0
}

// Err returns the last non-fatal write or rotate error, if any.
func (l *Logger) Err() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// Close closes the underlying file. Safe on a nil Logger.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
