package identity

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
)

// AuthorizedClients mirrors SSH's authorized_keys: a plain-text list of
// Ed25519 public keys (base64, one per line) this node trusts (Fase 1 §2).
type AuthorizedClients struct {
	path string
	keys map[string]bool // base64(pubkey) -> true
}

// LoadAuthorizedClients reads path, treating a missing file as an empty
// list — a fresh node trusts nobody until keys are explicitly authorized.
func LoadAuthorizedClients(path string) (*AuthorizedClients, error) {
	ac := &AuthorizedClients{path: path, keys: map[string]bool{}}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return ac, nil
	}
	if err != nil {
		return nil, fmt.Errorf("identity: open authorized_clients %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := decodePublicKey(line); err != nil {
			return nil, fmt.Errorf("identity: %s: invalid public key %q: %w", path, line, err)
		}
		ac.keys[line] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("identity: read authorized_clients %s: %w", path, err)
	}
	return ac, nil
}

// IsAuthorized reports whether pub is in the trust list (Fase 1 §3 step 4).
func (ac *AuthorizedClients) IsAuthorized(pub ed25519.PublicKey) bool {
	return ac.keys[encodePublicKey(pub)]
}

// Add trusts pub and persists the updated list to disk.
func (ac *AuthorizedClients) Add(pub ed25519.PublicKey) error {
	ac.keys[encodePublicKey(pub)] = true
	return ac.save()
}

// Remove revokes trust in pub and persists the updated list to disk.
func (ac *AuthorizedClients) Remove(pub ed25519.PublicKey) error {
	delete(ac.keys, encodePublicKey(pub))
	return ac.save()
}

// save rewrites the file with a sorted key list so it stays diff-friendly
// and deterministic across saves (map iteration order is not).
func (ac *AuthorizedClients) save() error {
	lines := make([]string, 0, len(ac.keys))
	for k := range ac.keys {
		lines = append(lines, k)
	}
	sort.Strings(lines)

	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(ac.path, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("identity: write authorized_clients %s: %w", ac.path, err)
	}
	return nil
}

func encodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

func decodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
