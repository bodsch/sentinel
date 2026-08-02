package version

import (
	"strings"
	"testing"
)

func TestGetIncludesGoVersion(t *testing.T) {
	t.Parallel()

	info := Get()
	if info.Version != Version {
		t.Errorf("Get().Version = %q, want %q", info.Version, Version)
	}
	if !strings.HasPrefix(info.GoVersion, "go") {
		t.Errorf("Get().GoVersion = %q, want a value starting with %q", info.GoVersion, "go")
	}
}

func TestInfoString(t *testing.T) {
	t.Parallel()

	info := Info{Version: "0.1.0", Commit: "abc123", BuildDate: "2026-01-01T00:00:00Z", GoVersion: "go1.26"}
	s := info.String()
	for _, want := range []string{"sentinel", "0.1.0", "abc123", "2026-01-01T00:00:00Z", "go1.26"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}
