package ignore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gitignore "github.com/sabhiram/go-gitignore"
)

// FileName is the exclusion file Load looks for at the root of a synced
// directory — deliberately not literally ".gitignore", since a directory
// being synced isn't necessarily a git repo and its real .gitignore (if
// any) may exclude things for reasons that have nothing to do with sync
// (e.g. it might deliberately track node_modules).
const FileName = ".fileshareignore"

// DefaultPatterns are excluded even without a .fileshareignore present —
// the same regenerable-noise baseline internal/watch used to hardcode
// directly before this package existed. A real .fileshareignore layers on
// top of these (including negating them with a leading '!'), it doesn't
// replace them.
var DefaultPatterns = []string{
	".git/",
	"node_modules/",
	"__pycache__/",
	".venv/",
	"venv/",
	"target/",
	"vendor/",
	"dist/",
	"build/",
	".fileshare_tmp_*/", // Fase 4's atomic-commit sandbox — never source content
}

// Matcher decides whether a root-relative, slash-separated path should be
// excluded from a Fase 5 Watcher session. The zero value is not usable —
// construct one with Load.
type Matcher struct {
	gi *gitignore.GitIgnore
}

// Load reads root's .fileshareignore (gitignore syntax) if present and
// compiles it together with DefaultPatterns. A missing .fileshareignore is
// not an error — it just means DefaultPatterns alone.
func Load(root string) (*Matcher, error) {
	path := filepath.Join(root, FileName)

	lines := make([]string, len(DefaultPatterns))
	copy(lines, DefaultPatterns)

	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("ignore: read %s: %w", path, err)
		}
	} else {
		lines = append(lines, strings.Split(string(data), "\n")...)
	}

	return &Matcher{gi: gitignore.CompileIgnoreLines(lines...)}, nil
}

// Match reports whether relPath should be excluded. A nil *Matcher matches
// nothing — the zero-configuration fallback for a caller that never called
// Load, rather than a nil-pointer panic.
func (m *Matcher) Match(relPath string) bool {
	if m == nil {
		return false
	}
	return m.gi.MatchesPath(filepath.ToSlash(relPath))
}
