package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Identity is a node's Ed25519 keypair plus the machine ID it claims in the
// Fase 1 handshake.
type Identity struct {
	MachineID  string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

type onDisk struct {
	MachineID  string `json:"machine_id"`
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"`
}

// Generate creates a new random identity for machineID.
func Generate(machineID string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate keypair: %w", err)
	}
	return &Identity{MachineID: machineID, PublicKey: pub, PrivateKey: priv}, nil
}

// Load reads an identity from path. If path does not exist yet, it
// generates a fresh identity for machineID and persists it first — the
// first-boot bootstrap described in Fase 4 §1 ("si no existen, las
// autogenera en el primer arranque").
func Load(path, machineID string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		id, genErr := Generate(machineID)
		if genErr != nil {
			return nil, genErr
		}
		if saveErr := id.Save(path); saveErr != nil {
			return nil, saveErr
		}
		return id, nil
	}
	if err != nil {
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}

	var d onDisk
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("identity: decode %s: %w", path, err)
	}
	return &Identity{
		MachineID:  d.MachineID,
		PublicKey:  ed25519.PublicKey(d.PublicKey),
		PrivateKey: ed25519.PrivateKey(d.PrivateKey),
	}, nil
}

// Save persists the identity to path with owner-only permissions (Fase 4
// §1: "bloquea los permisos del archivo a nivel POSIX (chmod 600)"). On
// Windows this maps to the read-only attribute rather than real POSIX ACLs
// — a known platform gap, not something this package can fix.
func (id *Identity) Save(path string) error {
	d := onDisk{MachineID: id.MachineID, PublicKey: id.PublicKey, PrivateKey: id.PrivateKey}
	data, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("identity: encode: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("identity: create dir %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("identity: write %s: %w", path, err)
	}
	return nil
}

// Sign signs data with the identity's private key.
func (id *Identity) Sign(data []byte) []byte {
	return ed25519.Sign(id.PrivateKey, data)
}

// Verify reports whether sig is a valid signature of data by pub.
func Verify(pub ed25519.PublicKey, data, sig []byte) bool {
	return ed25519.Verify(pub, data, sig)
}
