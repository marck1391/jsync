package handshake

import (
	"testing"
	"time"

	"jsync/internal/identity"
)

func TestSessionStoreCreateGet(t *testing.T) {
	store := NewSessionStore()
	initiator, err := identity.Generate("peer-machine")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	sess, err := store.Create(initiator.MachineID, initiator.PublicKey, Params{MaxPayloadBytes: 1024}, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sess.ID == "" {
		t.Fatal("Create: expected non-empty session ID")
	}

	got, ok := store.Get(sess.ID)
	if !ok {
		t.Fatal("Get: expected session to be found")
	}
	if got.ID != sess.ID {
		t.Errorf("Get returned ID %q, want %q", got.ID, sess.ID)
	}

	if _, ok := store.Get("does-not-exist"); ok {
		t.Error("Get: expected unknown session ID to return false")
	}
}

func TestSessionStoreExpiry(t *testing.T) {
	store := NewSessionStore()
	initiator, err := identity.Generate("peer-machine")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	sess, err := store.Create(initiator.MachineID, initiator.PublicKey, Params{}, "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Force expiry without waiting SessionTTL out in real time.
	store.mu.Lock()
	store.sessions[sess.ID].ExpiresAt = time.Now().Add(-1 * time.Second)
	store.mu.Unlock()

	if _, ok := store.Get(sess.ID); ok {
		t.Error("Get: expected expired session to be treated as missing")
	}
}

func TestSessionStoreCloseAndSweep(t *testing.T) {
	store := NewSessionStore()
	initiator, err := identity.Generate("peer-machine")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	live, err := store.Create(initiator.MachineID, initiator.PublicKey, Params{}, "")
	if err != nil {
		t.Fatalf("Create (live): %v", err)
	}
	expired, err := store.Create(initiator.MachineID, initiator.PublicKey, Params{}, "")
	if err != nil {
		t.Fatalf("Create (expired): %v", err)
	}

	store.mu.Lock()
	store.sessions[expired.ID].ExpiresAt = time.Now().Add(-1 * time.Second)
	store.mu.Unlock()

	if n := store.Sweep(); n != 1 {
		t.Errorf("Sweep removed %d sessions, want 1", n)
	}
	if _, ok := store.Get(live.ID); !ok {
		t.Error("Sweep: must not remove a live session")
	}

	store.Close(live.ID)
	if _, ok := store.Get(live.ID); ok {
		t.Error("Close: expected session to be gone after explicit close")
	}
}
