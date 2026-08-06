//go:build windows

package pipeline

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isSymlinkUnsupportedPlatform covers the two ways Windows refuses to
// create a symlink: ERROR_PRIVILEGE_NOT_HELD (no Developer Mode, not
// elevated — the common case) and ERROR_NOT_SUPPORTED (a filesystem that
// doesn't support symlinks at all, e.g. FAT32).
func isSymlinkUnsupportedPlatform(err error) bool {
	return errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) || errors.Is(err, windows.ERROR_NOT_SUPPORTED)
}
