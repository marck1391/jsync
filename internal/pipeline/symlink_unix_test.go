//go:build !windows

package pipeline

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestIsSymlinkUnsupportedPlatformDetectsWrappedErrno(t *testing.T) {
	for _, errno := range []error{syscall.EPERM, syscall.ENOTSUP} {
		raw := &os.LinkError{Op: "symlink", New: "/tmp/x", Err: errno}
		wrapped := fmt.Errorf("pipeline: symlink %s -> %s: %w", "/tmp/x", "target", raw)

		if !isSymlinkUnsupportedPlatform(wrapped) {
			t.Errorf("isSymlinkUnsupportedPlatform should detect %v wrapped a layer deep", errno)
		}
	}
}

func TestIsSymlinkUnsupportedPlatformRejectsOtherErrors(t *testing.T) {
	if isSymlinkUnsupportedPlatform(errors.New("some other error")) {
		t.Error("isSymlinkUnsupportedPlatform should not misclassify an unrelated error")
	}
	if isSymlinkUnsupportedPlatform(&os.LinkError{Op: "symlink", New: "/tmp/x", Err: syscall.ENOENT}) {
		t.Error("isSymlinkUnsupportedPlatform should not match a different errno")
	}
}
