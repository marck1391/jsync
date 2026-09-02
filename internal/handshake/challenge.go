package handshake

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"jsync/internal/identity"
)

// ClockSkew is the maximum allowed difference between a Request's Timestamp
// and the responder's local clock (Fase 1 §3 step 2: "si la diferencia es
// mayor a 5 segundos, descarta la petición").
const ClockSkew = 5 * time.Second

var (
	ErrProtocolVersion = errors.New("handshake: incompatible protocol version")
	ErrClockSkew       = errors.New("handshake: timestamp outside allowed clock skew")
	ErrBadSignature    = errors.New("handshake: signature verification failed")
	ErrReplay          = errors.New("handshake: nonce already seen")
	ErrNotAuthorized   = errors.New("handshake: public key not in authorized_clients")
)

// BuildRequest signs a new challenge as id, requesting destPath as the
// write target and direction as either a one-shot Fase 2 transfer or a
// standing Fase 5 Watcher (Fase 1 §3 step 1). Pass an empty destPath for a
// handshake that isn't about to write anything to disk (none exist yet,
// but nothing here requires it to be non-empty).
func BuildRequest(id *identity.Identity, destPath string, direction Direction, encrypt bool) (*Request, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("handshake: generate nonce: %w", err)
	}

	req := &Request{
		ProtocolVersion:    ProtocolVersion,
		MachineID:          id.MachineID,
		PublicKey:          []byte(id.PublicKey),
		Timestamp:          time.Now().UTC(),
		Nonce:              nonce,
		RequestedDestPath:  destPath,
		RequestedDirection: direction,
		RequestedEncrypt:   encrypt,
	}
	req.Signature = id.Sign(req.SignedPayload())
	return req, nil
}

// ReplayGuard rejects a nonce it has already accepted. Timestamp-window
// filtering alone is not replay protection — two distinct legitimate
// requests can land inside the same ClockSkew window — so this is what
// actually delivers Fase 1 §3 step 2's "previene ataques de repetición".
type ReplayGuard struct {
	mu   sync.Mutex
	seen map[[16]byte]time.Time
}

// NewReplayGuard returns an empty guard.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{seen: map[[16]byte]time.Time{}}
}

// Check records nonce if unseen and returns nil, or ErrReplay if it was
// already accepted within ClockSkew. It also opportunistically evicts
// entries older than ClockSkew so the map never grows past what the replay
// window actually requires.
func (g *ReplayGuard) Check(nonce [16]byte, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	for n, seenAt := range g.seen {
		if now.Sub(seenAt) > ClockSkew {
			delete(g.seen, n)
		}
	}

	if _, ok := g.seen[nonce]; ok {
		return ErrReplay
	}
	g.seen[nonce] = now
	return nil
}

// VerifyRequest runs the full responder-side validation of Fase 1 §3 steps
// 1-4 in cheapest-first order: protocol version, clock skew, signature,
// replay, and finally ACL lookup.
func VerifyRequest(req *Request, authorized *identity.AuthorizedClients, guard *ReplayGuard, now time.Time) error {
	if req.ProtocolVersion != ProtocolVersion {
		return ErrProtocolVersion
	}

	skew := now.Sub(req.Timestamp)
	if skew < 0 {
		skew = -skew
	}
	if skew > ClockSkew {
		return ErrClockSkew
	}

	if len(req.PublicKey) != ed25519.PublicKeySize {
		return ErrBadSignature
	}
	pub := ed25519.PublicKey(req.PublicKey)
	if !ed25519.Verify(pub, req.SignedPayload(), req.Signature) {
		return ErrBadSignature
	}

	if guard != nil {
		if err := guard.Check(req.Nonce, now); err != nil {
			return err
		}
	}

	if !authorized.IsAuthorized(pub) {
		return ErrNotAuthorized
	}

	return nil
}
