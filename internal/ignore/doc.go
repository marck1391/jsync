// Package ignore parses .jsyncignore files (gitignore syntax: globs,
// negation with !, comments) via github.com/sabhiram/go-gitignore rather
// than hand-rolling glob semantics — those have enough real edge cases
// (anchoring, **, character classes) that reusing a well-exercised parser
// is worth the dependency. DefaultPatterns ships a built-in skip list
// (node_modules, .git, vendor, dist, build, __pycache__, .venv, target...)
// so common cases work with zero configuration (Fase 5).
package ignore
