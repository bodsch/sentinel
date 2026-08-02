package config

import (
	"strings"
	"testing"
)

// TestExplicitZeroDurationRejected verifies that an explicit non-positive
// interval/timeout is rejected rather than being mistaken for "unset" and
// silently defaulted (review finding #5).
func TestExplicitZeroDurationRejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name:    "explicit interval 0s",
			yaml:    "targets:\n  - name: x\n    interval: 0s\n    http:\n      url: https://a.example\n",
			wantSub: "interval must be greater than zero",
		},
		{
			name:    "explicit timeout 0s",
			yaml:    "targets:\n  - name: x\n    timeout: 0s\n    http:\n      url: https://a.example\n",
			wantSub: "timeout must be greater than zero",
		},
		{
			name:    "defaults interval 0s propagates to target",
			yaml:    "defaults:\n  interval: 0s\ntargets:\n  - name: x\n    http:\n      url: https://a.example\n",
			wantSub: "interval must be greater than zero",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseResolve(t, tc.yaml)
			if err == nil {
				t.Fatalf("expected %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestUnsetDurationStillDefaults confirms the fix does not break the normal
// case: an unset interval/timeout still falls back to the built-in default.
func TestUnsetDurationStillDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, "targets:\n  - name: x\n    http:\n      url: https://a.example\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := cfg.Targets[0].ResolvedInterval(); got != defaultInterval {
		t.Errorf("interval = %v, want %v", got, defaultInterval)
	}
	if got := cfg.Targets[0].ResolvedTimeout(); got != defaultTimeout {
		t.Errorf("timeout = %v, want %v", got, defaultTimeout)
	}
}

// TestEmptyTagValueRejected covers review finding #3.
func TestEmptyTagValueRejected(t *testing.T) {
	t.Parallel()

	_, err := parseResolve(t, "targets:\n  - name: x\n    tags:\n      environment: \"  \"\n    http:\n      url: https://a.example\n")
	if err == nil || !strings.Contains(err.Error(), "must not have empty values") {
		t.Fatalf("expected empty-tag-value error, got: %v", err)
	}
}

// TestEmptyBodyRegexRejected covers review finding #4.
func TestEmptyBodyRegexRejected(t *testing.T) {
	t.Parallel()

	_, err := parseResolve(t, "targets:\n  - name: x\n    http:\n      url: https://a.example\n      expect:\n        body_regex:\n          - \"\"\n")
	if err == nil || !strings.Contains(err.Error(), "body_regex must not be empty") {
		t.Fatalf("expected empty-regex error, got: %v", err)
	}
}

// TestEmptyFileReportsNoTargets covers review finding #2: an empty or
// comment-only document must yield the clear "no targets defined" message, not
// an opaque parse error.
func TestEmptyFileReportsNoTargets(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "   \n  \n", "# only a comment\n"} {
		_, err := parseResolve(t, in)
		if err == nil || !strings.Contains(err.Error(), "no targets defined") {
			t.Fatalf("input %q: expected \"no targets defined\", got: %v", in, err)
		}
	}
}

// TestDefaultsPointerNotAliased covers review finding #1: inherited HTTP pointer
// fields must be independent copies, so mutating one target's resolved value
// does not affect another target or the defaults block.
func TestDefaultsPointerNotAliased(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
defaults:
  http:
    max_redirects: 5
targets:
  - name: a
    http:
      url: https://a.example
  - name: b
    http:
      url: https://b.example
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	a, b := cfg.Targets[0].HTTP, cfg.Targets[1].HTTP
	if a.MaxRedirects == b.MaxRedirects {
		t.Fatal("targets share the same *MaxRedirects pointer (aliasing)")
	}

	*a.MaxRedirects = 999
	if got := b.ResolvedMaxRedirects(); got != 5 {
		t.Fatalf("mutating target a changed target b: b.max_redirects = %d, want 5", got)
	}
	if got := *cfg.Defaults.HTTP.MaxRedirects; got != 5 {
		t.Fatalf("mutating target a changed the defaults block: defaults.max_redirects = %d, want 5", got)
	}
}

// TestURLCredentialsRejected covers review finding #7.
func TestURLCredentialsRejected(t *testing.T) {
	t.Parallel()

	_, err := parseResolve(t, "targets:\n  - name: x\n    http:\n      url: https://user:pass@a.example\n")
	if err == nil || !strings.Contains(err.Error(), "must not embed credentials") {
		t.Fatalf("expected credentials-in-URL error, got: %v", err)
	}
}
