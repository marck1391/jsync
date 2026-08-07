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
	".fileshare/",       // internal/config's default home for identity/prekeys/authorized_clients — see config.defaults(); never source content, and never something you want a peer receiving
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
//
// If root exists but isn't a directory (Fase 2's `fileshare share`
// supports sharing a single file directly, not just a directory tree),
// there's no directory to look inside for a .fileshareignore, so
// DefaultPatterns alone applies — checked via an explicit os.Stat rather
// than just letting the os.ReadFile below fail and treating any error as
// "not present": on Linux, filepath.Join(root, FileName) where root is a
// file resolves as ENOTDIR, which errors.Is(err, os.ErrNotExist) does
// *not* recognize (only ENOENT does) — confirmed on a real Linux VM, this
// would otherwise hard-fail `fileshare share` on a single file there,
// while happening to work on Windows by coincidence of a different
// underlying error.
func Load(root string) (*Matcher, error) {
	lines := make([]string, len(DefaultPatterns))
	copy(lines, DefaultPatterns)

	if info, statErr := os.Stat(root); statErr != nil || info.IsDir() {
		path := filepath.Join(root, FileName)
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("ignore: read %s: %w", path, err)
			}
		} else {
			lines = append(lines, strings.Split(string(data), "\n")...)
		}
	}

	return &Matcher{gi: gitignore.CompileIgnoreLines(lines...)}, nil
}

// Match reports whether relPath should be excluded. A nil *Matcher matches
// nothing — the zero-configuration fallback for a caller that never called
// Load, rather than a nil-pointer panic.
//
// relPath doesn't need a trailing slash even when it names a directory a
// caller is about to decide whether to filepath.SkipDir: Match tries it as
// given first, and if that doesn't match, retries with a trailing slash
// appended. go-gitignore's MatchesPath only recognizes a directory-only
// pattern (one ending in "/", like every entry in DefaultPatterns) against
// a query that itself ends in "/" — confirmed directly against the
// library: a bare directory name like ".fileshare" silently fails to
// match its own directory-only pattern, even though every file underneath
// it (which always has a "/" somewhere in its relPath) matches correctly.
// Without this, a caller relying on Match's result to skip descending into
// an excluded directory would walk into it anyway — every real caller in
// this project does exactly that (internal/watch's registerTree,
// internal/pipeline's walkAndAdd/EstimateSendSize, internal/syncfs's
// ScanManifest) — and fall back to catching each file inside
// individually, which still keeps secrets from actually leaking (a file's
// relPath always contains a "/" once nested at all) but defeats the
// point of skipping the subtree, and leaves an empty directory entry
// behind on the other end. The tradeoff: a plain *file* whose name
// exactly matches a directory-only pattern (e.g. a file literally named
// "node_modules", no extension) now also matches — gitignore itself
// distinguishes that case and this doesn't, accepted as vanishingly
// unlikely for the noise patterns DefaultPatterns deals with.
func (m *Matcher) Match(relPath string) bool {
	if m == nil {
		return false
	}
	relPath = filepath.ToSlash(relPath)
	if m.gi.MatchesPath(relPath) {
		return true
	}
	if !strings.HasSuffix(relPath, "/") {
		return m.gi.MatchesPath(relPath + "/")
	}
	return false
}
