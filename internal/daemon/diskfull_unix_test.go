//go:build !windows

package daemon

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestIsDiskFullPlatformDetectsWrappedENOSPC(t *testing.T) {
	raw := &os.PathError{Op: "write", Path: "/tmp/x", Err: syscall.ENOSPC}
	// Multiple layers, matching how extract.go/receiver.go actually wrap
	// errors (%w all the way up) before this ever sees them.
	wrapped := fmt.Errorf("pipeline: write %s: %w", "/tmp/x", raw)
	wrapped = fmt.Errorf("receive/extract: %w", wrapped)

	if !isDiskFullPlatform(wrapped) {
		t.Error("isDiskFullPlatform should detect ENOSPC wrapped several layers deep")
	}
}

func TestIsDiskFullPlatformRejectsOtherErrors(t *testing.T) {
	if isDiskFullPlatform(errors.New("some other error")) {
		t.Error("isDiskFullPlatform should not misclassify an unrelated error")
	}
	if isDiskFullPlatform(&os.PathError{Op: "open", Path: "/tmp/x", Err: syscall.ENOENT}) {
		t.Error("isDiskFullPlatform should not match a different errno")
	}
}
