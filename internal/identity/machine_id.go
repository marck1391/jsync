package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// NewMachineID returns a short, host-flavored default identifier for when
// config.yaml does not set machine_id explicitly (Fase 4 §1). It is not the
// trust anchor — the Ed25519 public key is — this is just a human-readable
// label used to route handshake subjects.
func NewMachineID() (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("identity: generate machine id suffix: %w", err)
	}

	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "node"
	}
	return fmt.Sprintf("%s-%s", host, hex.EncodeToString(suffix[:])), nil
}
