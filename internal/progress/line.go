package progress

import "fmt"

// lineWidth is padded to so a shorter line fully overwrites a longer
// previous one when printed with a leading \r and no trailing newline —
// without this, leftover characters from "123.4 MiB / 200.0 MiB (61%)"
// would still be visible after it shrinks back to "0 B" on the next
// attempt's first ping.
const lineWidth = 50

// Line renders a single-line, \r-prefixed progress update for
// bytesReceived out of totalBytes, meant to be printed with no trailing
// newline so the next call overwrites it in place (same convention
// tar/rsync use for terminal progress). totalBytes <= 0 means unknown —
// internal/pipeline.EstimateSendSize is an upfront estimate, not a
// guarantee, and can be 0 if it failed or the peer is too old to send one;
// Line falls back to reporting bytes received with no percentage rather
// than dividing by zero.
//
// Decoupled from internal/daemon.Status on purpose (plain int64s in, a
// string out) — same reasoning as this project's other small
// cross-package interfaces (see CLAUDE.md): this package renders, it
// doesn't need to know the wire shape of what's transferring it data.
func Line(bytesReceived, totalBytes int64) string {
	var content string
	if totalBytes <= 0 {
		content = fmt.Sprintf("receiving: %s", humanBytes(bytesReceived))
	} else {
		pct := float64(bytesReceived) / float64(totalBytes) * 100
		if pct > 100 {
			// EstimateSendSize is an estimate: a file that changed after
			// being marked "already resumed" can push actual bytes past
			// it. Clamp rather than show a nonsensical >100%.
			pct = 100
		}
		content = fmt.Sprintf("receiving: %s / %s (%.0f%%)", humanBytes(bytesReceived), humanBytes(totalBytes), pct)
	}
	return "\r" + padRight(content, lineWidth)
}

func padRight(s string, width int) string {
	for len([]rune(s)) < width {
		s += " "
	}
	return s
}

// humanBytes renders n bytes as a short, human-scaled string (B/KiB/MiB/...).
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
