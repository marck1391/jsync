package watch

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testTimeout = 5 * time.Second

func collectEvents(t *testing.T, changes <-chan ChangeEvent, errs <-chan error, deadline time.Duration) []ChangeEvent {
	t.Helper()
	var events []ChangeEvent
	timeout := time.After(deadline)
	for {
		select {
		case ev, ok := <-changes:
			if !ok {
				return events
			}
			events = append(events, ev)
		case err, ok := <-errs:
			if ok {
				t.Logf("watch error: %v", err)
			}
		case <-timeout:
			return events
		}
	}
}

func TestFileWatcher_DetectsCreateWriteRemove(t *testing.T) {
	dir := t.TempDir()

	fw := NewFileWatcher(30*time.Millisecond, DefaultBufferSize, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes, errs := fw.Watch(ctx, dir)
	defer fw.Close()

	target := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	events := collectEvents(t, changes, errs, testTimeout)
	var sawCreate bool
	for _, ev := range events {
		if ev.RelPath == "file.txt" && ev.Kind == ChangeModified {
			sawCreate = true
		}
	}
	if !sawCreate {
		t.Fatalf("expected a ChangeModified event for file.txt, got %+v", events)
	}
}

func TestFileWatcher_DebounceCoalescesSaveStorm(t *testing.T) {
	dir := t.TempDir()

	fw := NewFileWatcher(100*time.Millisecond, DefaultBufferSize, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes, errs := fw.Watch(ctx, dir)
	defer fw.Close()

	target := filepath.Join(dir, "final.txt")
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(target, []byte{byte(i)}, 0o644); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(5 * time.Millisecond)
	}

	events := collectEvents(t, changes, errs, testTimeout)
	var targetEvents []ChangeEvent
	for _, ev := range events {
		if ev.RelPath == "final.txt" {
			targetEvents = append(targetEvents, ev)
		}
	}
	if len(targetEvents) != 1 {
		t.Errorf("got %d events for final.txt, want exactly 1 (debounced): %+v", len(targetEvents), targetEvents)
	}
}

func TestFileWatcher_DetectsRemove(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "gone.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatalf("setup write: %v", err)
	}

	fw := NewFileWatcher(30*time.Millisecond, DefaultBufferSize, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes, errs := fw.Watch(ctx, dir)
	defer fw.Close()

	// Give registerTree a moment to index the pre-existing file before
	// removing it — handleRemove only schedules an event for paths it
	// already knows about (fw.fileDir), matching how a real sync session
	// would have picked it up on attach.
	time.Sleep(50 * time.Millisecond)

	if err := os.Remove(target); err != nil {
		t.Fatalf("remove: %v", err)
	}

	events := collectEvents(t, changes, errs, testTimeout)
	var sawRemove bool
	for _, ev := range events {
		if ev.RelPath == "gone.txt" && ev.Kind == ChangeRemoved {
			sawRemove = true
		}
	}
	if !sawRemove {
		t.Fatalf("expected a ChangeRemoved event for gone.txt, got %+v", events)
	}
}

// TestFileWatcher_RenamePreservesCorrelation is the whole point of
// diverging from indexer's watcher (see doc.go): a rename must arrive as a
// single ChangeRenamed event with both OldRelPath and RelPath set, not as
// an uncorrelated remove+create pair — that's what lets Fase 5 mirror a
// rename with one os.Rename on the remote side instead of re-transferring
// the file.
func TestFileWatcher_RenamePreservesCorrelation(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "before.txt")
	if err := os.WriteFile(oldPath, []byte("content"), 0o644); err != nil {
		t.Fatalf("setup write: %v", err)
	}

	fw := NewFileWatcher(30*time.Millisecond, DefaultBufferSize, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes, errs := fw.Watch(ctx, dir)
	defer fw.Close()

	time.Sleep(50 * time.Millisecond) // let registerTree index before.txt

	newPath := filepath.Join(dir, "after.txt")
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatalf("rename: %v", err)
	}

	events := collectEvents(t, changes, errs, testTimeout)

	var renameEvents, removeEvents, createEvents int
	var got ChangeEvent
	for _, ev := range events {
		switch {
		case ev.Kind == ChangeRenamed && ev.RelPath == "after.txt":
			renameEvents++
			got = ev
		case ev.Kind == ChangeRemoved && (ev.RelPath == "before.txt" || ev.RelPath == "after.txt"):
			removeEvents++
		case ev.Kind == ChangeModified && (ev.RelPath == "before.txt" || ev.RelPath == "after.txt"):
			createEvents++
		}
	}

	if runtime.GOOS == "windows" {
		if renameEvents != 1 {
			t.Fatalf("got %d ChangeRenamed events, want exactly 1: all events=%+v", renameEvents, events)
		}
		if got.OldRelPath != "before.txt" {
			t.Errorf("OldRelPath = %q, want %q", got.OldRelPath, "before.txt")
		}
		if removeEvents != 0 || createEvents != 0 {
			t.Errorf("rename should not also produce remove/create events: removes=%d creates=%d", removeEvents, createEvents)
		}
	} else {
		// Documented gap on non-Windows backends (see dirwatcher_notify.go):
		// falls back to an uncorrelated remove+create pair.
		if renameEvents != 0 {
			t.Errorf("did not expect rename correlation on this platform, got %d ChangeRenamed events", renameEvents)
		}
	}
}

func TestFileWatcher_SkipsDefaultIgnoredDirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}

	fw := NewFileWatcher(30*time.Millisecond, DefaultBufferSize, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes, errs := fw.Watch(ctx, dir)
	defer fw.Close()

	if err := os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "index.js"), []byte("noise"), 0o644); err != nil {
		t.Fatalf("write under node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("signal"), 0o644); err != nil {
		t.Fatalf("write real.txt: %v", err)
	}

	events := collectEvents(t, changes, errs, testTimeout)
	for _, ev := range events {
		if ev.RelPath != "" && ev.RelPath != "real.txt" {
			t.Errorf("unexpected event for ignored path: %+v", ev)
		}
	}
}

// stubMatcher is a minimal PathMatcher for testing the wiring itself,
// independent of internal/ignore's real gitignore parsing (that package
// has its own tests) — proves NewFileWatcher's matcher parameter actually
// gets consulted, not just that nil is backward compatible.
type stubMatcher struct{ ignoredSuffix string }

func (m stubMatcher) Match(relPath string) bool {
	return strings.HasSuffix(relPath, m.ignoredSuffix)
}

func TestFileWatcher_HonorsCustomPathMatcher(t *testing.T) {
	dir := t.TempDir()

	fw := NewFileWatcher(30*time.Millisecond, DefaultBufferSize, stubMatcher{ignoredSuffix: ".secret"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	changes, errs := fw.Watch(ctx, dir)
	defer fw.Close()

	if err := os.WriteFile(filepath.Join(dir, "creds.secret"), []byte("noise"), 0o644); err != nil {
		t.Fatalf("write creds.secret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("signal"), 0o644); err != nil {
		t.Fatalf("write real.txt: %v", err)
	}

	events := collectEvents(t, changes, errs, testTimeout)
	for _, ev := range events {
		if ev.RelPath != "" && ev.RelPath != "real.txt" {
			t.Errorf("unexpected event for path excluded by the custom matcher: %+v", ev)
		}
	}
}
