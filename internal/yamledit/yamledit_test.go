package yamledit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadMissingFileIsEmptyDoc(t *testing.T) {
	doc, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	root := DocumentRoot(&doc)
	if root.Kind != yaml.MappingNode || len(root.Content) != 0 {
		t.Fatalf("expected empty mapping root, got kind=%d len=%d", root.Kind, len(root.Content))
	}
}

func TestSetPreservesCommentsAndOrder(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "jsync.yaml")
	original := "# top note\nrole: hub          # inline note\nport: 4300\n"
	if err := os.WriteFile(cfg, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	doc, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	root := DocumentRoot(&doc)
	SetString(root, "host", "0.0.0.0") // new key
	SetInt(root, "port", 4400)         // replace existing

	buf, err := Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(cfg, buf, 0o600); err != nil {
		t.Fatal(err)
	}

	got, _ := os.ReadFile(cfg)
	s := string(got)
	for _, want := range []string{"# top note", "# inline note", "role: hub", "host: 0.0.0.0", "port: 4400"} {
		if !strings.Contains(s, want) {
			t.Errorf("rewritten file missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "port: 4300") {
		t.Errorf("old port value not replaced:\n%s", s)
	}
	// port must round-trip as an int, not a quoted string.
	var parsed struct {
		Port int `yaml:"port"`
	}
	if err := yaml.Unmarshal(got, &parsed); err != nil || parsed.Port != 4400 {
		t.Errorf("port did not re-parse as int: port=%d err=%v", parsed.Port, err)
	}
}

func TestEnsureSequencePromotesScalarAndDedups(t *testing.T) {
	var doc yaml.Node
	root := DocumentRoot(&doc)
	Set(root, "allowed_dest_paths", Scalar("/srv/one"))

	seq, err := EnsureSequence(root, "allowed_dest_paths")
	if err != nil {
		t.Fatal(err)
	}
	if seq.Kind != yaml.SequenceNode || len(seq.Content) != 1 {
		t.Fatalf("scalar not promoted to 1-item sequence: kind=%d len=%d", seq.Kind, len(seq.Content))
	}
	if !AppendUnique(seq, "/srv/two") {
		t.Fatal("AppendUnique(/srv/two) should report a change")
	}
	if AppendUnique(seq, "/srv/one") {
		t.Fatal("AppendUnique(/srv/one) is a duplicate, should report no change")
	}
	if AppendUnique(seq, "/srv/two/") {
		t.Fatal("trailing-slash variant should dedup via SamePath")
	}
	if len(seq.Content) != 2 {
		t.Fatalf("sequence should hold 2 entries, has %d", len(seq.Content))
	}
}

func TestEnsureSequenceRejectsMapping(t *testing.T) {
	var doc yaml.Node
	root := DocumentRoot(&doc)
	Set(root, "x", Mapping())
	if _, err := EnsureSequence(root, "x"); err == nil {
		t.Fatal("EnsureSequence over a mapping should error")
	}
}

func TestEnsureMappingCreatesAndReuses(t *testing.T) {
	var doc yaml.Node
	root := DocumentRoot(&doc)

	m1, err := EnsureMapping(root, "nodes")
	if err != nil {
		t.Fatal(err)
	}
	SetString(m1, "vm-01", "ID-1")

	m2, err := EnsureMapping(root, "nodes")
	if err != nil {
		t.Fatal(err)
	}
	if m1 != m2 {
		t.Fatal("EnsureMapping should return the same node on the second call")
	}
	if Get(m2, "vm-01").Value != "ID-1" {
		t.Fatal("existing entry lost")
	}
}

func TestDeleteReturnsOldValue(t *testing.T) {
	var doc yaml.Node
	root := DocumentRoot(&doc)
	SetString(root, "gone", "value")
	old := Delete(root, "gone")
	if old == nil || old.Value != "value" {
		t.Fatalf("Delete should return the removed value node, got %v", old)
	}
	if Get(root, "gone") != nil {
		t.Fatal("key still present after Delete")
	}
	if Delete(root, "absent") != nil {
		t.Fatal("Delete of an absent key should return nil")
	}
}

func TestAtomicWriteCreatesParentDir(t *testing.T) {
	target := filepath.Join(t.TempDir(), "a", "b", "c.yaml")
	if err := AtomicWrite(target, []byte("k: v\n"), 0o600); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "k: v\n" {
		t.Fatalf("read back: %q err=%v", got, err)
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}
