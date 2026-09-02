package auditlog_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jsync/internal/auditlog"
)

func TestOpenLogAndListRoundTrip(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()

	lg, err := auditlog.Open(dir, root, "sess-1")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	lg.Log(auditlog.Record{OpID: 1, Dir: "in", Origin: "peer", Op: "write", RelPath: "a.txt", Outcome: "applied"})
	lg.Log(auditlog.Record{OpID: 2, Dir: "out", Origin: "me", Op: "remove", RelPath: "b.txt", Outcome: "published"})
	lg.Log(auditlog.Record{OpID: 3, Dir: "in", Origin: "peer", Op: "write", RelPath: "c.txt", Outcome: "conflict", ConflictPath: "/x/c.txt.conflict-peer-1"})
	if err := lg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if lg.Err() != nil {
		t.Fatalf("Logger.Err after clean run: %v", lg.Err())
	}

	recs, err := auditlog.List(dir, auditlog.Query{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("List returned %d records, want 3", len(recs))
	}
	// Sorted by time then OpID — all logged in this order within the same
	// instant, so OpID is the tiebreak.
	for i, want := range []uint64{1, 2, 3} {
		if recs[i].OpID != want {
			t.Errorf("recs[%d].OpID = %d, want %d", i, recs[i].OpID, want)
		}
		if recs[i].Session != "sess-1" {
			t.Errorf("recs[%d].Session = %q, want the Open session", i, recs[i].Session)
		}
		if recs[i].Time.IsZero() {
			t.Errorf("recs[%d].Time is zero — Log should stamp it", i)
		}
	}
	if recs[2].ConflictPath == "" {
		t.Error("conflict record lost its ConflictPath through the round trip")
	}

	// Scoping List to the same root must return the same set...
	scoped, err := auditlog.List(dir, auditlog.Query{Root: root})
	if err != nil {
		t.Fatalf("List(root): %v", err)
	}
	if len(scoped) != 3 {
		t.Fatalf("List scoped to root returned %d, want 3", len(scoped))
	}
	// ...and a different root must return nothing.
	other, err := auditlog.List(dir, auditlog.Query{Root: t.TempDir()})
	if err != nil {
		t.Fatalf("List(other root): %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("List scoped to an unrelated root returned %d, want 0", len(other))
	}
}

func TestRootsSidecar(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	absRoot, _ := filepath.Abs(root)

	lg, err := auditlog.Open(dir, root, "s")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	lg.Close()

	roots, err := auditlog.Roots(dir)
	if err != nil {
		t.Fatalf("Roots: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("Roots returned %d entries, want 1", len(roots))
	}
	for _, got := range roots {
		if got != absRoot {
			t.Errorf("sidecar root = %q, want %q", got, absRoot)
		}
	}
}

func TestListFilters(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	lg, err := auditlog.Open(dir, root, "")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	lg.Log(auditlog.Record{OpID: 1, Time: base, Session: "s1", Op: "write", RelPath: "src/a.go", Outcome: "applied"})
	lg.Log(auditlog.Record{OpID: 2, Time: base.Add(time.Hour), Session: "s2", Op: "write", RelPath: "docs/b.md", Outcome: "applied"})
	lg.Log(auditlog.Record{OpID: 3, Time: base.Add(2 * time.Hour), Session: "s2", Op: "remove", RelPath: "src/c.go", Outcome: "applied"})
	lg.Close()

	bySession, err := auditlog.List(dir, auditlog.Query{Session: "s2"})
	if err != nil {
		t.Fatalf("List(session): %v", err)
	}
	if len(bySession) != 2 {
		t.Fatalf("session filter returned %d, want 2", len(bySession))
	}

	byPath, err := auditlog.List(dir, auditlog.Query{Path: "src/"})
	if err != nil {
		t.Fatalf("List(path): %v", err)
	}
	if len(byPath) != 2 {
		t.Fatalf("path filter returned %d, want 2", len(byPath))
	}

	bySince, err := auditlog.List(dir, auditlog.Query{Since: base.Add(90 * time.Minute)})
	if err != nil {
		t.Fatalf("List(since): %v", err)
	}
	if len(bySince) != 1 || bySince[0].OpID != 3 {
		t.Fatalf("since filter returned %+v, want just OpID 3", bySince)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	lg, err := auditlog.Open(dir, root, "s")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	lg.SetMaxBytes(600) // a handful of records per generation

	const n = 200
	for i := 0; i < n; i++ {
		lg.Log(auditlog.Record{OpID: uint64(i + 1), Dir: "in", Op: "write", RelPath: "f.txt", Outcome: "applied"})
	}
	lg.Close()

	// Rotation must have happened...
	if m, _ := filepath.Glob(filepath.Join(dir, "*.jsonl.1")); len(m) == 0 {
		t.Fatal("no rotated *.jsonl.1 file after writing well past the threshold")
	}

	recs, err := auditlog.List(dir, auditlog.Query{Root: root})
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	// ...it's a bounded ring, so old history is dropped: fewer than n, but
	// more than one generation's worth (proving multiple backups are kept,
	// not just one).
	if len(recs) >= n {
		t.Fatalf("List returned %d records; rotation should have dropped the oldest (< %d)", len(recs), n)
	}
	if len(recs) < 10 {
		t.Fatalf("List returned only %d records; expected several retained generations, not just one backup", len(recs))
	}

	// What survives is the most-recent contiguous run, in order, ending at n.
	for i := 1; i < len(recs); i++ {
		if recs[i].OpID != recs[i-1].OpID+1 {
			t.Fatalf("retained OpIDs are not contiguous/ordered: %d then %d", recs[i-1].OpID, recs[i].OpID)
		}
	}
	if got := recs[len(recs)-1].OpID; got != n {
		t.Fatalf("newest retained OpID = %d, want %d", got, n)
	}
}

func TestListToleratesTornLine(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()
	lg, err := auditlog.Open(dir, root, "s")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	lg.Log(auditlog.Record{OpID: 1, Op: "write", RelPath: "a", Outcome: "applied"})
	lg.Log(auditlog.Record{OpID: 2, Op: "write", RelPath: "b", Outcome: "applied"})
	lg.Close()

	// Simulate a process killed mid-write: a partial JSON fragment with no
	// trailing newline appended to the file.
	logFile, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	f, err := os.OpenFile(logFile[0], os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	f.WriteString(`{"op_id":3,"op":"write","rel_pa`)
	f.Close()

	recs, err := auditlog.List(dir, auditlog.Query{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("List returned %d records, want 2 (the torn line must be skipped)", len(recs))
	}
}

func TestNilLoggerIsNoop(t *testing.T) {
	var lg *auditlog.Logger
	// None of these may panic on a nil Logger — the "feature off" contract.
	lg.Log(auditlog.Record{Op: "write"})
	lg.SetMaxBytes(10)
	if lg.Err() != nil {
		t.Errorf("nil Logger.Err() = %v, want nil", lg.Err())
	}
	if err := lg.Close(); err != nil {
		t.Errorf("nil Logger.Close() = %v, want nil", err)
	}
}

func TestOpenAppendsAcrossSessions(t *testing.T) {
	dir := t.TempDir()
	root := t.TempDir()

	lg1, err := auditlog.Open(dir, root, "sess-1")
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	lg1.Log(auditlog.Record{OpID: 1, Op: "write", RelPath: "a", Outcome: "applied"})
	lg1.Close()

	lg2, err := auditlog.Open(dir, root, "sess-2")
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	lg2.Log(auditlog.Record{OpID: 1, Op: "write", RelPath: "b", Outcome: "applied"})
	lg2.Close()

	recs, err := auditlog.List(dir, auditlog.Query{Root: root})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("List returned %d, want 2 — the second session should have appended to the same file", len(recs))
	}
	got := []string{recs[0].Session, recs[1].Session}
	if !(strings.Join(got, ",") == "sess-1,sess-2") {
		t.Errorf("sessions = %v, want [sess-1 sess-2]", got)
	}

	logs, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(logs) != 1 {
		t.Fatalf("found %d log files, want exactly 1 (same root -> same file)", len(logs))
	}
}
