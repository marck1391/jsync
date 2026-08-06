// Package ignore parses .fileshareignore files (gitignore-style globs,
// negation, per-directory nesting) and ships a built-in default skip list
// (node_modules, .git, vendor, dist, build, __pycache__, .venv, target...)
// shared with indexer's walker.IsSkippedDir so common cases work with zero
// configuration (Fase 5).
package ignore
