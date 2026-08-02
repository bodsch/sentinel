// Package version exposes build information for the Sentinel binary. The values
// are stamped at build time via -ldflags (see the Makefile); when built without
// stamping they carry the "dev" defaults below.
package version

import "runtime"

// Build variables. These are overridden at link time with:
//
//	-ldflags "-X bodsch.me/sentinel/pkg/version.Version=... \
//	          -X bodsch.me/sentinel/pkg/version.Commit=...  \
//	          -X bodsch.me/sentinel/pkg/version.BuildDate=..."
var (
	// Version is the semantic version of the build (e.g. "0.1.0").
	Version = "dev"
	// Commit is the git commit the build was produced from.
	Commit = "unknown"
	// BuildDate is the build timestamp in RFC 3339 form.
	BuildDate = "unknown"
)

// Info is a snapshot of build metadata.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
}

// Get returns the current build information.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
	}
}

// String renders the build info as a single human-readable line.
func (i Info) String() string {
	return "sentinel " + i.Version + " (commit " + i.Commit + ", built " + i.BuildDate + ", " + i.GoVersion + ")"
}
