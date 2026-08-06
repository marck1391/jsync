package pipeline

// isSymlinkUnsupported reports whether err is (or wraps) the platform's
// "can't create a symlink here" error — isSymlinkUnsupportedPlatform is
// defined per-OS in symlink_unix.go/symlink_windows.go. A var, not a plain
// function call, on purpose: it lets a test substitute a fake classifier
// to exercise ExtractArchive's skip-not-abort branch (extract.go)
// deterministically, regardless of whether the machine running the test
// actually has (or lacks) symlink privileges.
//
// This exists because Windows requires Developer Mode (or an elevated
// process) to create a symlink at all — confirmed on a real, unprivileged
// Windows machine during development, not a hypothetical: os.Symlink
// there fails with "A required privilege is not held by the client."
// Since this project's central use case is Host↔VM (often Windows↔Linux),
// an unprivileged Windows receiver is a realistic scenario, not an edge
// case — so a single unsupported symlink skips (ExtractArchive continues
// with the rest of the tree) instead of aborting the whole transfer, the
// one deliberate exception to this package's usual "any per-entry problem
// aborts the session" rule. That rule still applies to a symlink whose
// *target* escapes the sandbox (see extract.go's safeSymlinkTarget) — this
// classifier is only ever consulted for "unsupported here", never for a
// security violation.
var isSymlinkUnsupported = isSymlinkUnsupportedPlatform
