package progress

import (
	"strings"
	"testing"
)

func TestLineWithKnownTotal(t *testing.T) {
	got := Line(512*1024, 1024*1024) // 0.5 MiB of 1.0 MiB = 50%
	if !strings.HasPrefix(got, "\r") {
		t.Errorf("Line should start with \\r to overwrite the previous line, got %q", got)
	}
	if !strings.Contains(got, "50%") {
		t.Errorf("Line = %q, want it to contain 50%%", got)
	}
	if !strings.Contains(got, "/") {
		t.Errorf("Line = %q, want a X / Y shape when total is known", got)
	}
}

func TestLineWithUnknownTotal(t *testing.T) {
	got := Line(2048, 0)
	if strings.Contains(got, "%") {
		t.Errorf("Line with unknown total should not show a percentage, got %q", got)
	}
	if !strings.Contains(got, "2.0 KiB") {
		t.Errorf("Line = %q, want it to mention the bytes received", got)
	}
}

func TestLineClampsOverEstimate(t *testing.T) {
	// A resumed file that changed since the estimate was built can push
	// actual bytes past the estimate — must clamp to 100%, not show 150%.
	got := Line(150, 100)
	if !strings.Contains(got, "100%") {
		t.Errorf("Line = %q, want it clamped to 100%%", got)
	}
	if strings.Contains(got, "150%") {
		t.Errorf("Line = %q, should never show over 100%%", got)
	}
}

func TestLineIsPaddedToOverwritePreviousLongerLine(t *testing.T) {
	long := Line(123456789, 987654321)
	short := Line(0, 0)
	if len([]rune(short)) < len([]rune(long)) {
		t.Errorf("a short line (%d runes) should still be padded at least as wide as a longer one (%d runes) so it fully overwrites it in a terminal", len([]rune(short)), len([]rune(long)))
	}
}

func TestHumanBytesScales(t *testing.T) {
	cases := map[int64]string{
		500:                    "500 B",
		2048:                   "2.0 KiB",
		5 * 1024 * 1024:        "5.0 MiB",
		3 * 1024 * 1024 * 1024: "3.0 GiB",
	}
	for n, want := range cases {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
