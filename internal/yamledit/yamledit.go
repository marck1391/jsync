// Package yamledit holds the yaml.Node helpers that `jsync allow`,
// `jsync node`, `jsync configure` and `jsyncd install` all use to edit the
// jsync config file in place — key by key, so existing comments and key
// order survive a rewrite (a plain Unmarshal -> struct -> Marshal round trip
// would drop both). It is deliberately tiny and free of jsync-specific
// knowledge: callers decide which keys to touch.
package yamledit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Load reads path into a document node. A missing file is not an error — it
// yields a zero-valued (empty) node, which DocumentRoot turns into a fresh
// mapping. Any other read/parse failure is returned.
func Load(path string) (yaml.Node, error) {
	var doc yaml.Node
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return doc, nil
		}
		return doc, fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("parse %s: %w", path, err)
	}
	return doc, nil
}

// DocumentRoot returns doc's top mapping node, initialising an empty
// document (nil Kind) into a fresh mapping so callers can Set into it
// unconditionally.
func DocumentRoot(doc *yaml.Node) *yaml.Node {
	if doc.Kind == 0 {
		doc.Kind = yaml.DocumentNode
	}
	if len(doc.Content) == 0 {
		doc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	return doc.Content[0]
}

// Get returns the value node for key in a mapping node, or nil.
func Get(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// Set sets (or replaces) key -> val in a mapping node. When it replaces an
// existing value, any comments attached to the old value node are carried
// onto val — editing `port: 4222  # fixed` to a new number must not drop
// the "# fixed".
func Set(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			old := m.Content[i+1]
			if val.HeadComment == "" {
				val.HeadComment = old.HeadComment
			}
			if val.LineComment == "" {
				val.LineComment = old.LineComment
			}
			if val.FootComment == "" {
				val.FootComment = old.FootComment
			}
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content, Scalar(key), val)
}

// SetString is Set for a plain string value.
func SetString(m *yaml.Node, key, value string) { Set(m, key, Scalar(value)) }

// Delete removes key from a mapping node, returning its old value node (or
// nil if the key was absent).
func Delete(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			val := m.Content[i+1]
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return val
		}
	}
	return nil
}

// Scalar builds a plain double-quoted-safe string scalar node.
func Scalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

// IntScalar builds an unquoted integer scalar node, so a numeric config key
// (port, leaf_node_port) round-trips back into an int field rather than
// being written as a quoted string.
func IntScalar(n int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(n)}
}

// SetInt is Set for an integer value.
func SetInt(m *yaml.Node, key string, n int) { Set(m, key, IntScalar(n)) }

// Mapping returns an empty mapping node.
func Mapping() *yaml.Node { return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"} }

// Sequence returns an empty sequence node.
func Sequence() *yaml.Node { return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"} }

// EnsureMapping returns the mapping node at key, creating an empty one if
// the key is absent. It errors if the key exists but is not a mapping.
func EnsureMapping(m *yaml.Node, key string) (*yaml.Node, error) {
	n := Get(m, key)
	if n == nil {
		n = Mapping()
		Set(m, key, n)
		return n, nil
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%q is not a mapping", key)
	}
	return n, nil
}

// EnsureSequence returns the sequence node at key, creating an empty one if
// the key is absent and promoting a lone scalar (`key: one`) to a one-item
// sequence. It errors if the key exists as a mapping.
func EnsureSequence(m *yaml.Node, key string) (*yaml.Node, error) {
	n := Get(m, key)
	switch {
	case n == nil:
		n = Sequence()
		Set(m, key, n)
	case n.Kind == yaml.ScalarNode:
		scalar := *n
		*n = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{&scalar}}
	case n.Kind != yaml.SequenceNode:
		return nil, fmt.Errorf("%q is not a sequence", key)
	}
	return n, nil
}

// SamePath reports whether a and b denote the same location, ignoring
// trailing slashes and redundant separators (filepath.Clean), without
// otherwise rewriting either string.
func SamePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// AppendUnique appends value as a scalar to seq (verbatim — the caller
// decides the canonical form) unless a SamePath item is already present;
// returns whether it appended.
func AppendUnique(seq *yaml.Node, value string) bool {
	for _, item := range seq.Content {
		if item.Kind == yaml.ScalarNode && SamePath(item.Value, value) {
			return false
		}
	}
	seq.Content = append(seq.Content, Scalar(value))
	return true
}

// Marshal renders doc with a 2-space indent, matching what `jsync allow`
// has always written.
func Marshal(doc *yaml.Node) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encode yaml: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode yaml: %w", err)
	}
	return b.Bytes(), nil
}

// AtomicWrite writes data to path via a temp file + rename, creating path's
// parent directory first. A failed rename removes the temp file so a
// half-written config is never left behind.
func AtomicWrite(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
