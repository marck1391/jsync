//go:build !windows

package pipeline

import (
	"errors"
	"syscall"
)

// isSymlinkUnsupportedPlatform: Unix systems don't gate symlink creation
// behind a privilege the way Windows does, but EPERM/ENOTSUP cover the
// rare cases that do refuse it (a hardened environment, or an exotic
// filesystem without symlink support).
func isSymlinkUnsupportedPlatform(err error) bool {
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOTSUP)
}
