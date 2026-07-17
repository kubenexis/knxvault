// Package version holds KNXVault release and build metadata.
package version

// Link-time metadata (override via -ldflags -X).
var (
	// Version is the semantic release version.
	Version = "0.5.1"
	// Commit is the git commit hash baked in at build time.
	Commit = "unknown"
	// BuildID is a Unix epoch seconds identifier set at build time.
	BuildID = "0"
)
