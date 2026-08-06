//go:build !windows

package watch

import (
	"fmt"
	"path/filepath"

	"github.com/rjeczalik/notify"
)

// recursiveDirWatcher watches one directory tree via github.com/rjeczalik/
// notify's native recursive mode (a single kernel watch for the whole tree
// on Linux/inotify and macOS/FSEvents) — ported from indexer's internal/
// watch. notify was rejected as the Windows backend specifically because it
// has no overflow detection there; Windows is this project's tested,
// primary platform (see planv1's Fase 0), so it gets the hand-rolled
// ReadDirectoryChangesW implementation in winwatcher_windows.go.
//
// Known gap versus that Windows backend: rename/move correlation is NOT
// implemented here. notify's unified EventInfo doesn't expose inotify's
// cookie field (which pairs IN_MOVED_FROM/IN_MOVED_TO) or FSEvents'
// per-path rename flags through a portable API — getting it right needs
// platform-specific Sys() type assertions per OS, unverified without a
// macOS machine to test against, and this project's Linux/macOS support is
// portability-only for now (same posture indexer already took). A rename
// on these platforms is reported as a plain rawRemove for the old path and
// a separate rawCreate for the new one — Fase 5's rename-instead-of-
// retransfer optimization simply doesn't trigger there yet; correctness
// isn't affected, only that specific optimization.
//
// Overflow detection is also NOT reliably available through this backend.
// notify's inotify backend silently discards IN_Q_OVERFLOW internally
// (never surfaced to any EventInfo or error) and its own internal event
// channel is documented to silently drop events if the consumer falls
// behind ("dropped: receiver too slow", logged only to an internal debug
// facility) on every backend, including this one. ErrKernelBufferOverflow
// is therefore never sent by this file; a large event-count channel buffer
// (derived from bufSize) is the only mitigation.
type recursiveDirWatcher struct {
	root string
	nch  chan notify.EventInfo

	events   chan rawEvent
	errs     chan error
	closeErr chan struct{}
}

func newRecursiveDirWatcher(root string, bufSize uint) (*recursiveDirWatcher, error) {
	if bufSize == 0 {
		bufSize = DefaultBufferSize
	}
	// notify sizes its channel in events, not bytes. bufSize/16 keeps the
	// same order of magnitude as the Windows backend's fixed 4096-event
	// channel at the 64 KiB default, while still scaling with a larger
	// configured buffer size.
	chCap := int(bufSize / 16)
	if chCap < 256 {
		chCap = 256
	}

	nch := make(chan notify.EventInfo, chCap)
	recursive := root + string(filepath.Separator) + "..."
	if err := notify.Watch(recursive, nch, notify.Create, notify.Write, notify.Remove, notify.Rename); err != nil {
		return nil, fmt.Errorf("watch: notify.Watch %s: %w", root, err)
	}

	w := &recursiveDirWatcher{
		root:     root,
		nch:      nch,
		events:   make(chan rawEvent, chCap),
		errs:     make(chan error, 8),
		closeErr: make(chan struct{}),
	}
	go w.readLoop()
	return w, nil
}

func (w *recursiveDirWatcher) Close() error {
	select {
	case <-w.closeErr:
		return nil // already closed
	default:
		close(w.closeErr)
	}
	notify.Stop(w.nch)
	return nil
}

func (w *recursiveDirWatcher) readLoop() {
	for {
		select {
		case ei, ok := <-w.nch:
			if !ok {
				return
			}
			w.emit(ei)
		case <-w.closeErr:
			return
		}
	}
}

// emit maps notify's generic event set to the shared rawAction vocabulary.
// Rename here is always the vacated old-name side (notify's inotify
// encode(): Rename -> IN_MOVED_FROM, Create -> IN_CREATE|IN_MOVED_TO), so
// it collapses to rawRemove — the new-name side already arrives as its own
// separate Create event. See the type doc comment for why this doesn't
// correlate the pair into a rawRename the way winwatcher_windows.go does.
func (w *recursiveDirWatcher) emit(ei notify.EventInfo) {
	var action rawAction
	switch ei.Event() {
	case notify.Create:
		action = rawCreate
	case notify.Write:
		action = rawModify
	case notify.Remove, notify.Rename:
		action = rawRemove
	default:
		return
	}
	select {
	case w.events <- rawEvent{action: action, path: ei.Path()}:
	case <-w.closeErr:
	}
}
