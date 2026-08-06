//go:build windows

package watch

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// notifyFilter deliberately excludes FILE_NOTIFY_CHANGE_ATTRIBUTES/SECURITY:
// attribute-only (chmod-like) changes never reach the kernel buffer at all,
// so there is no "attributes-only event" case to filter in handleEvent.
const notifyFilter = windows.FILE_NOTIFY_CHANGE_FILE_NAME |
	windows.FILE_NOTIFY_CHANGE_DIR_NAME |
	windows.FILE_NOTIFY_CHANGE_LAST_WRITE

// recursiveDirWatcher watches one directory tree with a single native
// ReadDirectoryChangesW(bWatchSubtree=true) handle — ported from indexer's
// internal/watch, with one deliberate divergence: indexer's mapAction
// collapses FILE_ACTION_RENAMED_OLD_NAME/NEW_NAME straight down to
// rawRemove/rawCreate. This version pairs them into a single rawRename
// (see parseAndEmit) because Fase 5 needs the correlation — indexer never
// did, it only needed to know something changed.
//
// Only one ReadDirectoryChanges call is ever in flight on w.handle at a
// time (readLoop is strictly sequential), which is what makes it safe to
// reuse a single w.overlap across iterations and to leave its HEvent unset
// (GetOverlappedResult then waits on the file handle itself, which Win32
// only allows when there is no ambiguity about which operation signaled
// it — true here because there is always exactly one).
type recursiveDirWatcher struct {
	handle  windows.Handle
	root    string
	overlap windows.Overlapped
	buf     []byte

	// pendingOldName holds a FILE_ACTION_RENAMED_OLD_NAME path until the
	// NEW_NAME record that (per Microsoft's documented ordering guarantee)
	// immediately follows it arrives, so the pair can be emitted as one
	// rawRename. There is no independent cookie to correlate them by, on
	// Windows — only positional adjacency in the notification stream.
	pendingOldName string

	events   chan rawEvent
	errs     chan error
	closeErr chan struct{}
}

func newRecursiveDirWatcher(root string, bufSize uint) (*recursiveDirWatcher, error) {
	if bufSize == 0 {
		bufSize = DefaultBufferSize
	}
	pathPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return nil, fmt.Errorf("watch: encode path %s: %w", root, err)
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("watch: open %s: %w", root, err)
	}

	w := &recursiveDirWatcher{
		handle:   handle,
		root:     root,
		buf:      make([]byte, bufSize),
		events:   make(chan rawEvent, 4096),
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
	// Best-effort: unblocks readLoop's pending GetOverlappedResult wait even
	// if it raced past the closeErr check just before issuing the next
	// ReadDirectoryChanges call. CloseHandle below is the actual safety net
	// in that race — closing a handle with I/O pending aborts it too.
	_ = windows.CancelIoEx(w.handle, &w.overlap)
	return windows.CloseHandle(w.handle)
}

func (w *recursiveDirWatcher) sendErr(err error) bool {
	select {
	case w.errs <- err:
		return true
	case <-w.closeErr:
		return false
	}
}

func (w *recursiveDirWatcher) readLoop() {
	for {
		select {
		case <-w.closeErr:
			return
		default:
		}

		err := windows.ReadDirectoryChanges(w.handle, &w.buf[0], uint32(len(w.buf)), true, notifyFilter, nil, &w.overlap, 0)
		if err != nil {
			w.sendErr(fmt.Errorf("watch: ReadDirectoryChanges: %w", err))
			return
		}

		var n uint32
		err = windows.GetOverlappedResult(w.handle, &w.overlap, &n, true)
		if err != nil {
			if errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
				return // Close() canceled us, or the handle was closed
			}
			if errors.Is(err, windows.ERROR_NOTIFY_ENUM_DIR) {
				if !w.sendErr(ErrKernelBufferOverflow) {
					return
				}
				continue
			}
			w.sendErr(fmt.Errorf("watch: GetOverlappedResult: %w", err))
			return
		}
		if n == 0 {
			// Microsoft's docs: a zero-length result also indicates the
			// buffer overflowed (distinct from ERROR_NOTIFY_ENUM_DIR).
			if !w.sendErr(ErrKernelBufferOverflow) {
				return
			}
			continue
		}

		if !w.parseAndEmit(n) {
			return
		}
	}
}

// parseAndEmit walks the FILE_NOTIFY_INFORMATION records packed into
// w.buf[:n]. Names in a recursive watch are already root-relative and may
// contain subdirectory components (e.g. "sub\\dir\\file.go"), not just a
// basename — filepath.Join handles that transparently.
func (w *recursiveDirWatcher) parseAndEmit(n uint32) bool {
	var offset uint32
	for {
		raw := (*windows.FileNotifyInformation)(unsafe.Pointer(&w.buf[offset]))
		nameLen := int(raw.FileNameLength / 2)
		name := windows.UTF16ToString(unsafe.Slice(&raw.FileName, nameLen))
		full := filepath.Join(w.root, name)

		if !w.handleAction(raw.Action, full) {
			return false
		}

		if raw.NextEntryOffset == 0 {
			break
		}
		offset += raw.NextEntryOffset
		if offset >= n {
			break
		}
	}

	// A trailing OLD_NAME with no following NEW_NAME in this same buffer
	// (the pair got split across two ReadDirectoryChanges completions) —
	// flush it as a plain remove rather than holding it indefinitely; the
	// NEW_NAME that follows in the next buffer will then arrive with no
	// pending old name and fall back to being treated as a create (see
	// handleAction), same net result as indexer's unconditional collapse.
	if w.pendingOldName != "" {
		old := w.pendingOldName
		w.pendingOldName = ""
		select {
		case w.events <- rawEvent{action: rawRemove, path: old}:
		case <-w.closeErr:
			return false
		}
	}
	return true
}

func (w *recursiveDirWatcher) handleAction(action uint32, full string) bool {
	switch action {
	case windows.FILE_ACTION_RENAMED_OLD_NAME:
		// Don't emit yet — wait to see if NEW_NAME follows immediately.
		w.pendingOldName = full
		return true

	case windows.FILE_ACTION_RENAMED_NEW_NAME:
		if w.pendingOldName != "" {
			old := w.pendingOldName
			w.pendingOldName = ""
			select {
			case w.events <- rawEvent{action: rawRename, path: full, oldPath: old}:
				return true
			case <-w.closeErr:
				return false
			}
		}
		// No paired old name (split across buffers, or a name filtered out
		// by a future flush) — fall back to treating it as a plain create.
		select {
		case w.events <- rawEvent{action: rawCreate, path: full}:
			return true
		case <-w.closeErr:
			return false
		}

	case windows.FILE_ACTION_ADDED:
		select {
		case w.events <- rawEvent{action: rawCreate, path: full}:
			return true
		case <-w.closeErr:
			return false
		}

	case windows.FILE_ACTION_REMOVED:
		select {
		case w.events <- rawEvent{action: rawRemove, path: full}:
			return true
		case <-w.closeErr:
			return false
		}

	case windows.FILE_ACTION_MODIFIED:
		select {
		case w.events <- rawEvent{action: rawModify, path: full}:
			return true
		case <-w.closeErr:
			return false
		}

	default:
		return true
	}
}
