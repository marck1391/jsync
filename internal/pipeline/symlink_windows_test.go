//go:build windows

package pipeline

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsSymlinkUnsupportedPlatformDetectsWrappedErrno(t *testing.T) {
	for _, errno := range []error{windows.ERROR_PRIVILEGE_NOT_HELD, windows.ERROR_NOT_SUPPORTED} {
		raw := &os.LinkError{Op: "symlink", New: `C:\x`, Err: errno}
		wrapped := fmt.Errorf("pipeline: symlink %s -> %s: %w", `C:\x`, "target", raw)

		if !isSymlinkUnsupportedPlatform(wrapped) {
			t.Errorf("isSymlinkUnsupportedPlatform should detect %v wrapped a layer deep", errno)
		}
	}
}

func TestIsSymlinkUnsupportedPlatformRejectsOtherErrors(t *testing.T) {
	if isSymlinkUnsupportedPlatform(errors.New("some other error")) {
		t.Error("isSymlinkUnsupportedPlatform should not misclassify an unrelated error")
	}
	if isSymlinkUnsupportedPlatform(&os.LinkError{Op: "symlink", New: `C:\x`, Err: windows.ERROR_FILE_NOT_FOUND}) {
		t.Error("isSymlinkUnsupportedPlatform should not match a different Win32 error code")
	}
}
