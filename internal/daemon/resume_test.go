package daemon

import (
	"testing"
	"time"

	"filesharer/internal/identity"
)

func testPeerPub(t *testing.T) []byte {
	t.Helper()
	id, err := identity.Generate("peer")
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id.PublicKey
}

func TestResumeRegistryClaimConsumesEntry(t *testing.T) {
	r := NewResumeRegistry()
	peer := testPeerPub(t)
	r.Park(peer, "/dest", "/sandbox", map[string]string{"a.txt": "hash-a"}, time.Minute)

	sandboxDir, completed, ok := r.Claim(peer, "/dest")
	if !ok {
		t.Fatal("Claim: expected an entry")
	}
	if sandboxDir != "/sandbox" {
		t.Errorf("sandboxDir = %q, want %q", sandboxDir, "/sandbox")
	}
	if completed["a.txt"] != "hash-a" {
		t.Errorf("completed[a.txt] = %q, want %q", completed["a.txt"], "hash-a")
	}

	if _, _, ok := r.Claim(peer, "/dest"); ok {
		t.Error("second Claim should find nothing — the first Claim should have consumed the entry")
	}
}

func TestResumeRegistryPeekDoesNotConsume(t *testing.T) {
	r := NewResumeRegistry()
	peer := testPeerPub(t)
	r.Park(peer, "/dest", "/sandbox", map[string]string{"a.txt": "hash-a"}, time.Minute)

	files := r.Peek(peer, "/dest")
	if len(files) != 1 || files[0].RelPath != "a.txt" || files[0].ContentHash != "hash-a" {
		t.Fatalf("Peek result = %+v, want one entry {a.txt, hash-a}", files)
	}

	// Peek must not have consumed it — a real Claim right after should
	// still find it.
	if _, _, ok := r.Claim(peer, "/dest"); !ok {
		t.Error("Claim after Peek should still find the entry — Peek must not consume")
	}
}

func TestResumeRegistryPeekHidesExpiredEntry(t *testing.T) {
	r := NewResumeRegistry()
	peer := testPeerPub(t)
	r.Park(peer, "/dest", "/sandbox", map[string]string{"a.txt": "hash-a"}, -time.Second) // already expired

	if files := r.Peek(peer, "/dest"); files != nil {
		t.Errorf("Peek should hide an expired entry, got %+v", files)
	}
}

func TestResumeRegistryClaimRejectsExpiredEntry(t *testing.T) {
	r := NewResumeRegistry()
	peer := testPeerPub(t)
	r.Park(peer, "/dest", "/sandbox", map[string]string{"a.txt": "hash-a"}, -time.Second) // already expired

	if _, _, ok := r.Claim(peer, "/dest"); ok {
		t.Error("Claim should refuse an expired entry")
	}
}

func TestResumeRegistryDifferentPeersDontCollide(t *testing.T) {
	r := NewResumeRegistry()
	alice := testPeerPub(t)
	eve := testPeerPub(t)
	r.Park(alice, "/dest", "/sandbox-alice", map[string]string{"secret.txt": "alice-hash"}, time.Minute)

	if files := r.Peek(eve, "/dest"); files != nil {
		t.Errorf("a different peer must never see another peer's resume manifest, got %+v", files)
	}
	if _, _, ok := r.Claim(eve, "/dest"); ok {
		t.Error("a different peer must never be able to claim another peer's parked sandbox")
	}
}

func TestResumeRegistryReParkRefreshesExpiry(t *testing.T) {
	r := NewResumeRegistry()
	peer := testPeerPub(t)
	r.Park(peer, "/dest", "/sandbox", map[string]string{"a.txt": "hash-a"}, time.Minute)

	// Simulate a second failed attempt: claim, then park again with a
	// fresh grace period — the clock should measure from this Park, not
	// the first one.
	sandboxDir, completed, ok := r.Claim(peer, "/dest")
	if !ok {
		t.Fatal("Claim: expected the first entry")
	}
	completed["b.txt"] = "hash-b"
	r.Park(peer, "/dest", sandboxDir, completed, time.Minute)

	files := r.Peek(peer, "/dest")
	if len(files) != 2 {
		t.Fatalf("Peek after re-park = %+v, want 2 entries (a.txt and b.txt)", files)
	}
}

func TestResumeRegistrySweepRemovesOnlyExpired(t *testing.T) {
	r := NewResumeRegistry()
	alive := testPeerPub(t)
	dead := testPeerPub(t)
	r.Park(alive, "/dest-alive", "/sandbox-alive", nil, time.Hour)
	r.Park(dead, "/dest-dead", "/sandbox-dead", nil, time.Millisecond)

	now := time.Now().Add(time.Second) // past the "dead" entry's expiry
	expired := r.Sweep(now)

	if len(expired) != 1 || expired[0] != "/sandbox-dead" {
		t.Fatalf("Sweep returned %v, want exactly [/sandbox-dead]", expired)
	}
	if _, _, ok := r.Claim(alive, "/dest-alive"); !ok {
		t.Error("the still-alive entry should survive Sweep")
	}
	if _, _, ok := r.Claim(dead, "/dest-dead"); ok {
		t.Error("Sweep should have removed the expired entry from the registry, not just reported it")
	}
}

func TestResumeRegistryDestPathIsCleaned(t *testing.T) {
	r := NewResumeRegistry()
	peer := testPeerPub(t)
	r.Park(peer, "/dest/", "/sandbox", map[string]string{"a.txt": "hash-a"}, time.Minute)

	// A trailing slash (or other non-canonical spelling) must not be able
	// to dodge the registry key.
	if _, _, ok := r.Claim(peer, "/dest"); !ok {
		t.Error("Claim with a differently-spelled but equivalent destPath should still find the entry")
	}
}
