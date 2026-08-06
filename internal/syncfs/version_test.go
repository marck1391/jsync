package syncfs

import "testing"

func TestCompareVectorsEqual(t *testing.T) {
	a := VersionVector{"node-a": 2, "node-b": 1}
	b := VersionVector{"node-a": 2, "node-b": 1}
	if got := compareVectors(a, b); got != vectorEqual {
		t.Errorf("compareVectors(a, b) = %v, want vectorEqual", got)
	}
}

func TestCompareVectorsAAfterB(t *testing.T) {
	a := VersionVector{"node-a": 3, "node-b": 1}
	b := VersionVector{"node-a": 2, "node-b": 1}
	if got := compareVectors(a, b); got != vectorAAfterB {
		t.Errorf("compareVectors(a, b) = %v, want vectorAAfterB", got)
	}
	if got := compareVectors(b, a); got != vectorBAfterA {
		t.Errorf("compareVectors(b, a) = %v, want vectorBAfterA", got)
	}
}

func TestCompareVectorsConcurrent(t *testing.T) {
	a := VersionVector{"node-a": 1}
	b := VersionVector{"node-b": 1}
	if got := compareVectors(a, b); got != vectorConcurrent {
		t.Errorf("compareVectors(a, b) = %v, want vectorConcurrent", got)
	}
}

func TestCompareVectorsEmptyVsPopulated(t *testing.T) {
	empty := VersionVector{}
	populated := VersionVector{"node-a": 1}
	if got := compareVectors(populated, empty); got != vectorAAfterB {
		t.Errorf("compareVectors(populated, empty) = %v, want vectorAAfterB", got)
	}
}

func TestVersionStoreBumpIncrementsOwnComponent(t *testing.T) {
	s := NewVersionStore()
	v1 := s.Bump("f.txt", "node-a")
	if v1["node-a"] != 1 {
		t.Errorf("first Bump: node-a = %d, want 1", v1["node-a"])
	}
	v2 := s.Bump("f.txt", "node-a")
	if v2["node-a"] != 2 {
		t.Errorf("second Bump: node-a = %d, want 2", v2["node-a"])
	}
}

func TestVersionStoreReconcileAcceptsCausalUpdate(t *testing.T) {
	s := NewVersionStore()
	s.Bump("f.txt", "node-a") // simulates node-a's own local write (v=1), now "known"

	// A later write from node-a (v=2) causally follows v=1.
	incoming := VersionVector{"node-a": 2}
	safe, conflict := s.Reconcile("f.txt", incoming)
	if !safe || conflict {
		t.Errorf("Reconcile(v2 after v1) = safe=%v conflict=%v, want safe=true conflict=false", safe, conflict)
	}
}

func TestVersionStoreReconcileDropsStaleUpdate(t *testing.T) {
	s := NewVersionStore()
	s.byPathForTest()["f.txt"] = VersionVector{"node-a": 5}

	safe, conflict := s.Reconcile("f.txt", VersionVector{"node-a": 3})
	if safe || conflict {
		t.Errorf("Reconcile(stale) = safe=%v conflict=%v, want safe=false conflict=false", safe, conflict)
	}
}

func TestVersionStoreReconcileDetectsConcurrentConflict(t *testing.T) {
	s := NewVersionStore()
	s.byPathForTest()["f.txt"] = VersionVector{"node-a": 1}

	safe, conflict := s.Reconcile("f.txt", VersionVector{"node-b": 1})
	if safe || !conflict {
		t.Errorf("Reconcile(concurrent) = safe=%v conflict=%v, want safe=false conflict=true", safe, conflict)
	}

	// After a conflict, the stored vector should be the merge, so a
	// subsequent update causally following BOTH prior writes is accepted.
	safe2, conflict2 := s.Reconcile("f.txt", VersionVector{"node-a": 1, "node-b": 2})
	if !safe2 || conflict2 {
		t.Errorf("Reconcile(after merge) = safe=%v conflict=%v, want safe=true conflict=false", safe2, conflict2)
	}
}

// byPathForTest exposes the internal map for white-box setup in tests
// within this package — kept in a _test.go file so it never ships.
func (s *VersionStore) byPathForTest() map[string]VersionVector {
	return s.byPath
}
