package daemon

// isDiskFull reports whether err is (or wraps, via errors.Is down the
// whole %w chain) the platform's "no space left on device" error —
// isDiskFullPlatform is defined per-OS in diskfull_unix.go/diskfull_windows.go.
// A var, not a plain function call, on purpose: it lets a test substitute a
// fake classifier to exercise ReceiveSession's disk-full-vs-park branch
// (receiver.go) without needing to actually exhaust a disk.
var isDiskFull = isDiskFullPlatform
