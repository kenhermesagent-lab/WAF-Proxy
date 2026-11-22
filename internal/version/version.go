// Package version exposes build metadata for the binary and the API.
package version

// Values are overridden at build time with -ldflags.
var (
	// Version is the semantic version of this build, e.g. "1.0.0".
	Version = "1.17.2"
	// Commit is the git revision the binary was built from.
	Commit = "dev"
	// BuildDate is the RFC3339 build timestamp.
	BuildDate = "unknown"
)
