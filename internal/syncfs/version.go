package syncfs

import "sync"

// VersionVector maps machine_id -> a per-path logical clock: how many
// times that machine has written this specific path, as far as whoever
// holds the vector knows. Comparing two vectors for the same path is how
// Fase 5 tells a genuine update from a genuine conflict (Fase 5 §2)
// without relying on wall-clock timestamps, which can't be trusted to
// order events across machines with unsynchronized clocks.
type VersionVector map[string]uint64

func (v VersionVector) clone() VersionVector {
	out := make(VersionVector, len(v))
	for k, n := range v {
		out[k] = n
	}
	return out
}

// vectorOrder is the result of comparing two VersionVectors for the same
// path.
type vectorOrder int

const (
	vectorEqual      vectorOrder = iota // identical — a duplicate/re-delivery, not a new update
	vectorAAfterB                       // a causally happened after b: every component of a is >= the matching one in b, at least one strictly greater
	vectorBAfterA                       // the reverse: b happened after a
	vectorConcurrent                    // neither dominates — both sides advanced their own component without having seen the other's — a genuine conflict
)

func compareVectors(a, b VersionVector) vectorOrder {
	aGreater, bGreater := false, false
	seen := make(map[string]bool, len(a)+len(b))
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	for k := range seen {
		if a[k] > b[k] {
			aGreater = true
		}
		if b[k] > a[k] {
			bGreater = true
		}
	}
	switch {
	case aGreater && bGreater:
		return vectorConcurrent
	case aGreater:
		return vectorAAfterB
	case bGreater:
		return vectorBAfterA
	default:
		return vectorEqual
	}
}

// VersionStore tracks the last-known VersionVector per path. Safe for
// concurrent use. In-memory only — a Daemon restart forgets it, same
// documented limitation as Fase 1's SessionStore and Fase 3's pending
// One-Time PreKeys: a fresh Watcher session starts with a clean slate
// rather than risk stale conflict state from a previous run.
type VersionStore struct {
	mu     sync.Mutex
	byPath map[string]VersionVector
}

// NewVersionStore returns an empty store.
func NewVersionStore() *VersionStore {
	return &VersionStore{byPath: map[string]VersionVector{}}
}

// Bump increments machineID's component of relPath's vector — call this
// once, locally, right before publishing a local write, so the outgoing
// Event carries a vector proving "I've now written this path N times".
func (s *VersionStore) Bump(relPath, machineID string) VersionVector {
	s.mu.Lock()
	defer s.mu.Unlock()

	v := s.byPath[relPath].clone()
	if v == nil {
		v = VersionVector{}
	}
	v[machineID]++
	s.byPath[relPath] = v
	return v.clone()
}

// Reconcile compares incoming against what's stored for relPath and
// reports whether it's safe to Apply.
//
//   - safe=true: incoming causally follows (or exactly matches) what's
//     stored — apply it, and Reconcile has already adopted incoming as the
//     new stored vector.
//   - safe=false, conflict=false: incoming is stale (dominated by what's
//     already stored, or a mid-air duplicate already accounted for) —
//     drop it, nothing to do.
//   - safe=false, conflict=true: incoming and the stored vector are
//     concurrent — neither side had seen the other's write. The caller
//     must not overwrite the local file; see event.go's conflict-file
//     convention. Reconcile still merges the two vectors (component-wise
//     max) so the next comparison for this path is judged against
//     everything either side has seen so far, not just one of them.
func (s *VersionStore) Reconcile(relPath string, incoming VersionVector) (safe, conflict bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	local := s.byPath[relPath]
	switch compareVectors(incoming, local) {
	case vectorEqual:
		return false, false // already have exactly this — duplicate delivery
	case vectorAAfterB:
		s.byPath[relPath] = incoming.clone()
		return true, false
	case vectorBAfterA:
		return false, false // stale
	default: // vectorConcurrent
		merged := local.clone()
		if merged == nil {
			merged = VersionVector{}
		}
		for k, n := range incoming {
			if n > merged[k] {
				merged[k] = n
			}
		}
		s.byPath[relPath] = merged
		return false, true
	}
}
