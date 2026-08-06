//go:build windows

package daemon

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isDiskFullPlatform is diskfull_unix.go's Windows counterpart — see that
// file's doc comment. Windows surfaces a full disk as one of two distinct
// Win32 error codes depending on which API path hit it (ERROR_DISK_FULL
// from a plain write, ERROR_HANDLE_DISK_FULL from some buffered/handle-based
// paths) — both are checked.
func isDiskFullPlatform(err error) bool {
	return errors.Is(err, windows.ERROR_DISK_FULL) || errors.Is(err, windows.ERROR_HANDLE_DISK_FULL)
}
