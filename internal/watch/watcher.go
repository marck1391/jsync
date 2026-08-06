package watch

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ChangeKind classifies a debounced ChangeEvent.
type ChangeKind int

const (
	ChangeModified ChangeKind = iota // Write or Create
	ChangeRemoved                    // Remove, or a Rename this platform's backend couldn't correlate
	ChangeRenamed                    // OS-correlated rename/move — OldRelPath and RelPath are both set
	ChangeRescan                     // watcher lost integrity (kernel buffer overflow) — caller must fully resync
)

// ChangeEvent is one debounced, filtered, coalesced filesystem change.
type ChangeEvent struct {
	AbsPath string
	RelPath string // slash-separated, root-relative

	// OldAbsPath/OldRelPath are only set when Kind == ChangeRenamed.
	OldAbsPath string
	OldRelPath string

	Kind ChangeKind
}

// FileWatcher hides the platform watcher backend. Emits debounced, filtered
// events for one root directory.
type FileWatcher interface {
	Watch(ctx context.Context, root string) (<-chan ChangeEvent, <-chan error)
	Close() error
}

// DefaultDebounce coalesces editor atomic-save storms (write temp file,
// rewrite it, rename over the target) into one event per path.
const DefaultDebounce = 250 * time.Millisecond

// DefaultBufferSize is the OS-level watch buffer: the ReadDirectoryChangesW
// kernel read buffer on Windows, or an event-count floor derived from it on
// the notify-based backend (dirwatcher_notify.go).
const DefaultBufferSize = 64 * 1024

// ErrKernelBufferOverflow signals that the OS's filesystem-change
// notification channel dropped or lost events between the last delivered
// event and this one. Never ignore it — the watch loop responds with a
// ChangeRescan, and the caller must fully resync against the remote side
// rather than trust its incremental state. See winwatcher_windows.go and
// dirwatcher_notify.go for how (and, on non-Windows, how unreliably) each
// backend detects this.
var ErrKernelBufferOverflow = errors.New("watch: OS notification buffer overflowed, events lost")

// defaultSkipDirs is a placeholder exclusion list for common regenerable
// noise (build artifacts, dependency caches, VCS metadata) — a stand-in
// until internal/ignore's real .fileshareignore parsing exists (Fase 5).
// Directories in this list are never descended into and never reported.
var defaultSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	"target":       true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
}

// isSkippedDir also excludes Fase 4's own sandbox directories
// (.fileshare_tmp_<session_id>) — an in-flight transfer's staging area
// must never be picked up as source content by the watcher.
func isSkippedDir(name string) bool {
	return defaultSkipDirs[name] || strings.HasPrefix(name, ".fileshare_tmp_")
}

// rawAction is the platform-neutral action a backend reports for a path.
type rawAction int

const (
	rawCreate rawAction = iota
	rawRemove
	rawModify
	rawRename // oldPath -> path; both set on rawEvent
)

// rawEvent is one undebounced, unfiltered notification from a backend.
type rawEvent struct {
	action  rawAction
	path    string // absolute, OS-native separators; the new path for rawRename
	oldPath string // only set for rawRename
}

type pendingEvent struct {
	kind    ChangeKind
	absPath string
	relPath string
	oldAbs  string
	oldRel  string
}

// PathMatcher decides whether a root-relative, slash-separated path should
// be excluded from a Watcher session. internal/ignore.Matcher satisfies
// this by structural typing — this package deliberately doesn't import
// internal/ignore directly (same reasoning as pipeline's DeriveChainFunc
// callback: Fase 5's watcher core has no business knowing Fase 5's
// exclusion policy exists as a separate package, only that something can
// answer "is this path excluded").
type PathMatcher interface {
	Match(relPath string) bool
}

// fsWatcher is the FileWatcher implementation: a native recursive backend
// per platform (winwatcher_windows.go / dirwatcher_notify.go) feeding a
// single loop goroutine that debounces and filters.
type fsWatcher struct {
	debounce   time.Duration
	bufferSize uint
	matcher    PathMatcher // nil means "defaultSkipDirs only" — see excluded()

	w    *recursiveDirWatcher
	root string

	mu       sync.Mutex
	dirFiles map[string]map[string]bool // absDir -> set of relPath
	fileDir  map[string]string          // relPath -> absDir
}

// NewFileWatcher returns a FileWatcher. debounce <= 0 uses DefaultDebounce;
// bufferSize == 0 uses DefaultBufferSize. matcher may be nil, in which case
// only the hardcoded defaultSkipDirs fast-path applies (no .fileshareignore
// support) — every production caller should pass a real
// internal/ignore.Matcher; nil exists mainly so tests that don't care about
// exclusion don't need to construct one.
func NewFileWatcher(debounce time.Duration, bufferSize uint, matcher PathMatcher) FileWatcher {
	if debounce <= 0 {
		debounce = DefaultDebounce
	}
	if bufferSize == 0 {
		bufferSize = DefaultBufferSize
	}
	return &fsWatcher{
		debounce: debounce, bufferSize: bufferSize, matcher: matcher,
		dirFiles: map[string]map[string]bool{}, fileDir: map[string]string{},
	}
}

// excluded reports whether absPath (which must be under fw.root) should be
// dropped: either it's under a defaultSkipDirs directory (the cheap
// basename-only fast-path that also lets registerTree's WalkDir skip
// descending into e.g. node_modules entirely, not just filter it out after
// the fact), or fw.matcher says so via the full relative path.
func (fw *fsWatcher) excluded(absPath string) bool {
	if fw.underSkippedDir(absPath) || isSkippedDir(filepath.Base(absPath)) {
		return true
	}
	if fw.matcher == nil {
		return false
	}
	rel, err := filepath.Rel(fw.root, absPath)
	if err != nil {
		return false
	}
	return fw.matcher.Match(filepath.ToSlash(rel))
}

func (fw *fsWatcher) Watch(ctx context.Context, root string) (<-chan ChangeEvent, <-chan error) {
	changes := make(chan ChangeEvent)
	errs := make(chan error)

	absRoot, err := filepath.Abs(root)
	if err != nil {
		go func() {
			defer close(changes)
			defer close(errs)
			errs <- fmt.Errorf("resolve root %s: %w", root, err)
		}()
		return changes, errs
	}
	fw.root = absRoot

	w, err := newRecursiveDirWatcher(absRoot, fw.bufferSize)
	if err != nil {
		go func() {
			defer close(changes)
			defer close(errs)
			errs <- fmt.Errorf("create watcher: %w", err)
		}()
		return changes, errs
	}
	fw.w = w

	// Bookkeeping only — the recursive watch above already covers the whole
	// tree, so this never issues additional OS watch calls.
	fw.registerTree(absRoot)

	go fw.loop(ctx, changes, errs)
	return changes, errs
}

func (fw *fsWatcher) Close() error {
	if fw.w == nil {
		return nil
	}
	return fw.w.Close()
}

// registerTree walks dir, indexing every non-skipped file into
// dirFiles/fileDir without emitting any events. Used both for initial
// startup and for a live directory Create (files may have landed before
// the watch attached, or a directory with existing contents was moved in
// from outside the watched root — the OS reports only the top-level
// create/move, not each file inside).
func (fw *fsWatcher) registerTree(dir string) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // best-effort: one bad entry shouldn't abort registration
		}
		if d.IsDir() {
			if p != dir && fw.excluded(p) {
				return filepath.SkipDir
			}
			return nil
		}
		if fw.excluded(p) {
			return nil
		}

		rel, relErr := filepath.Rel(fw.root, p)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		parent := filepath.Dir(p)

		fw.mu.Lock()
		if fw.dirFiles[parent] == nil {
			fw.dirFiles[parent] = map[string]bool{}
		}
		fw.dirFiles[parent][rel] = true
		fw.fileDir[rel] = parent
		fw.mu.Unlock()
		return nil
	})
}

// underSkippedDir reports whether absPath lives inside a skipped directory
// at any depth below root. Needed because the recursive watch covers the
// whole tree unconditionally — the OS has no concept of "don't recurse
// into this subtree" — so events from inside a skip-dir still arrive here
// and must be dropped at this layer instead of never being registered in
// the first place (as registerTree's WalkDir does for the initial scan).
func (fw *fsWatcher) underSkippedDir(absPath string) bool {
	rel, err := filepath.Rel(fw.root, absPath)
	if err != nil {
		return false
	}
	for dir := filepath.Dir(rel); dir != "." && dir != string(filepath.Separator); {
		if isSkippedDir(filepath.Base(dir)) {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return false
}

func (fw *fsWatcher) loop(ctx context.Context, changes chan<- ChangeEvent, errs chan<- error) {
	defer close(changes)
	defer close(errs)

	pending := map[string]*time.Timer{}
	fire := make(chan pendingEvent)
	defer func() {
		for _, t := range pending {
			t.Stop()
		}
	}()

	schedule := func(key string, pe pendingEvent) {
		if t, ok := pending[key]; ok {
			t.Stop()
		}
		pending[key] = time.AfterFunc(fw.debounce, func() {
			select {
			case fire <- pe:
			case <-ctx.Done():
			}
		})
	}

	for {
		select {
		case ev := <-fw.w.events:
			fw.handleEvent(ctx, ev, schedule, changes)

		case pe := <-fire:
			delete(pending, debounceKey(pe))
			if pe.kind == ChangeRemoved {
				fw.forget(pe.relPath)
			} else if pe.kind == ChangeRenamed {
				fw.rename(pe.oldRel, pe.relPath)
			}
			select {
			case changes <- ChangeEvent{
				AbsPath: pe.absPath, RelPath: pe.relPath,
				OldAbsPath: pe.oldAbs, OldRelPath: pe.oldRel,
				Kind: pe.kind,
			}:
			case <-ctx.Done():
				return
			}

		case err := <-fw.w.errs:
			if errors.Is(err, ErrKernelBufferOverflow) {
				select {
				case changes <- ChangeEvent{Kind: ChangeRescan}:
				case <-ctx.Done():
					return
				}
				continue
			}
			select {
			case errs <- err:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

func debounceKey(pe pendingEvent) string {
	if pe.kind == ChangeRenamed {
		return "rename:" + pe.relPath
	}
	return "path:" + pe.relPath
}

func (fw *fsWatcher) forget(relPath string) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	if dir, ok := fw.fileDir[relPath]; ok {
		delete(fw.fileDir, relPath)
		if fw.dirFiles[dir] != nil {
			delete(fw.dirFiles[dir], relPath)
		}
	}
}

func (fw *fsWatcher) rename(oldRel, newRel string) {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	dir, ok := fw.fileDir[oldRel]
	if !ok {
		return
	}
	delete(fw.fileDir, oldRel)
	if fw.dirFiles[dir] != nil {
		delete(fw.dirFiles[dir], oldRel)
	}
	newDir := filepath.Dir(filepath.Join(fw.root, filepath.FromSlash(newRel)))
	if fw.dirFiles[newDir] == nil {
		fw.dirFiles[newDir] = map[string]bool{}
	}
	fw.dirFiles[newDir][newRel] = true
	fw.fileDir[newRel] = newDir
}

func (fw *fsWatcher) handleEvent(ctx context.Context, ev rawEvent, schedule func(string, pendingEvent), changes chan<- ChangeEvent) {
	switch ev.action {
	case rawCreate:
		fw.handleCreate(ctx, ev.path, schedule, changes)
	case rawModify:
		fw.handleWrite(ev.path, schedule)
	case rawRemove:
		fw.handleRemove(ev.path, schedule)
	case rawRename:
		fw.handleRename(ctx, ev.oldPath, ev.path, schedule, changes)
	}
}

func (fw *fsWatcher) handleCreate(ctx context.Context, absPath string, schedule func(string, pendingEvent), changes chan<- ChangeEvent) {
	if fw.excluded(absPath) {
		return
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return // vanished already or inaccessible — ignore
	}

	if info.IsDir() {
		fw.registerTree(absPath)
		fw.mu.Lock()
		rels := make([]string, 0, len(fw.dirFiles[absPath]))
		for rel := range fw.dirFiles[absPath] {
			rels = append(rels, rel)
		}
		fw.mu.Unlock()

		// Files may have landed before the watch attached — emit
		// immediately, not debounced: this is a one-time catch-up.
		for _, rel := range rels {
			select {
			case changes <- ChangeEvent{AbsPath: filepath.Join(fw.root, filepath.FromSlash(rel)), RelPath: rel, Kind: ChangeModified}:
			case <-ctx.Done():
				return
			}
		}
		return
	}

	fw.handleWrite(absPath, schedule)
}

func (fw *fsWatcher) handleWrite(absPath string, schedule func(string, pendingEvent)) {
	if fw.excluded(absPath) {
		return
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return
	}
	if info.IsDir() {
		return // directory modify events (e.g. a child was renamed) carry no useful payload here
	}

	rel, err := filepath.Rel(fw.root, absPath)
	if err != nil {
		return
	}
	rel = filepath.ToSlash(rel)
	parent := filepath.Dir(absPath)

	fw.mu.Lock()
	if fw.dirFiles[parent] == nil {
		fw.dirFiles[parent] = map[string]bool{}
	}
	fw.dirFiles[parent][rel] = true
	fw.fileDir[rel] = parent
	fw.mu.Unlock()

	schedule("path:"+rel, pendingEvent{kind: ChangeModified, absPath: absPath, relPath: rel})
}

func (fw *fsWatcher) handleRemove(absPath string, schedule func(string, pendingEvent)) {
	fw.mu.Lock()
	files, isDir := fw.dirFiles[absPath]
	if isDir {
		rels := make([]string, 0, len(files))
		for rel := range files {
			rels = append(rels, rel)
		}
		delete(fw.dirFiles, absPath)
		for _, rel := range rels {
			delete(fw.fileDir, rel)
		}
		fw.mu.Unlock()

		for _, rel := range rels {
			schedule("path:"+rel, pendingEvent{kind: ChangeRemoved, absPath: filepath.Join(fw.root, filepath.FromSlash(rel)), relPath: rel})
		}
		return
	}

	rel, err := filepath.Rel(fw.root, absPath)
	if err != nil {
		fw.mu.Unlock()
		return
	}
	rel = filepath.ToSlash(rel)
	_, tracked := fw.fileDir[rel]
	fw.mu.Unlock()

	if !tracked {
		return // never-registered path (e.g. under a skip-dir) — ignore
	}
	schedule("path:"+rel, pendingEvent{kind: ChangeRemoved, absPath: absPath, relPath: rel})
}

// handleRename handles an OS-correlated rename/move pair (Fase 5's whole
// reason for diverging from indexer): oldAbsPath no longer exists,
// newAbsPath is what it's now called. Both files and directories can be
// renamed; a directory rename is reported as one ChangeRenamed event
// regardless of how much is underneath it — the receiver mirrors it with a
// single os.Rename (Fase 5), not a re-transfer of every descendant.
func (fw *fsWatcher) handleRename(ctx context.Context, oldAbsPath, newAbsPath string, schedule func(string, pendingEvent), changes chan<- ChangeEvent) {
	oldSkipped := fw.excluded(oldAbsPath)
	newSkipped := fw.excluded(newAbsPath)

	switch {
	case oldSkipped && newSkipped:
		return
	case oldSkipped && !newSkipped:
		// Moved from an ignored subtree into a tracked one: as far as the
		// remote side is concerned this is a fresh create, not a rename —
		// it never had the old path to begin with.
		fw.handleCreate(ctx, newAbsPath, schedule, changes)
		return
	case !oldSkipped && newSkipped:
		// Moved into an ignored subtree: the remote side should forget it,
		// same as a plain remove.
		fw.handleRemove(oldAbsPath, schedule)
		return
	}

	oldRel, err := filepath.Rel(fw.root, oldAbsPath)
	if err != nil {
		return
	}
	newRel, err := filepath.Rel(fw.root, newAbsPath)
	if err != nil {
		return
	}
	oldRel = filepath.ToSlash(oldRel)
	newRel = filepath.ToSlash(newRel)

	schedule("rename:"+newRel, pendingEvent{
		kind:    ChangeRenamed,
		absPath: newAbsPath, relPath: newRel,
		oldAbs: oldAbsPath, oldRel: oldRel,
	})
}
