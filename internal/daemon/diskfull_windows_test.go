//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsDiskFullPlatformDetectsWrappedErrorDiskFull(t *testing.T) {
	for _, errno := range []error{windows.ERROR_DISK_FULL, windows.ERROR_HANDLE_DISK_FULL} {
		raw := &os.PathError{Op: "write", Path: `C:\x`, Err: errno}
		// Multiple layers, matching how extract.go/receiver.go actually
		// wrap errors (%w all the way up) before this ever sees them.
		wrapped := fmt.Errorf("pipeline: write %s: %w", `C:\x`, raw)
		wrapped = fmt.Errorf("receive/extract: %w", wrapped)

		if !isDiskFullPlatform(wrapped) {
			t.Errorf("isDiskFullPlatform should detect %v wrapped several layers deep", errno)
		}
	}
}

func TestIsDiskFullPlatformRejectsOtherErrors(t *testing.T) {
	if isDiskFullPlatform(errors.New("some other error")) {
		t.Error("isDiskFullPlatform should not misclassify an unrelated error")
	}
	if isDiskFullPlatform(&os.PathError{Op: "open", Path: `C:\x`, Err: windows.ERROR_FILE_NOT_FOUND}) {
		t.Error("isDiskFullPlatform should not match a different Win32 error code")
	}
}
