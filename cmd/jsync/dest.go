package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// resolveDestPath turns a relative `<dest-path>` (the part after the ":" in
// `<target>:<dest-path>`) into an absolute one, resolved against the
// directory jsync is being run from — never against anything on the jsyncd
// side. This is deliberately a client-only, single-path resolution: the
// multi-root policy (`allowed_dest_paths`) lives entirely in jsyncd, and the
// client stays unaware of it. The daemon's containment check then runs on
// the absolute result exactly as before, so it still has to land inside one
// of the daemon's allowed roots.
//
// A path that already looks absolute on *any* platform (POSIX "/x", Windows
// "C:\x") is only cleaned, not rewritten — a Windows client must still be
// able to address a Linux daemon with `peer:/srv/inbox`.
func resolveDestPath(dest string) (string, error) {
	if destLooksAbsolute(dest) {
		// Pass through verbatim — including a POSIX "/srv/x" seen by a
		// Windows client, which filepath.Clean would corrupt into
		// "\srv\x". The daemon cleans and range-checks it either way.
		return dest, nil
	}
	abs, err := filepath.Abs(dest)
	if err != nil {
		return "", fmt.Errorf("resolve dest %q against the current directory: %w", dest, err)
	}
	return abs, nil
}

// destLooksAbsolute mirrors internal/pipeline.looksAbsolute so a cross-OS
// target path isn't mangled by filepath.Abs on the wrong platform.
func destLooksAbsolute(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return true
	}
	if len(p) >= 2 && p[1] == ':' {
		c := p[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return filepath.IsAbs(p)
}
