//go:build !windows

package daemon

import (
	"errors"
	"syscall"
)

// isDiskFullPlatform reports whether err is (or wraps) ENOSPC — "no space
// left on device". Fase 4's original error-handling table wants disk-full
// treated differently from every other Fase 2 receive failure
// (internal/daemon/receiver.go): the sandbox is deleted immediately
// instead of parked for resume, since holding onto a half-received
// sandbox on an already-full disk is actively harmful — the next attempt
// needs that space back, not a resume that still can't fit.
func isDiskFullPlatform(err error) bool {
	return errors.Is(err, syscall.ENOSPC)
}
