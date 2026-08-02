package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// parseResolve is a test helper: parse, apply defaults, validate.
func parseResolve(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	return cfg, cfg.Validate()
}

func TestValidMinimalConfig(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
targets:
  - name: homepage
    http:
      url: https://example.org
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(cfg.Targets))
	}
	tg := cfg.Targets[0]
	if got, want := tg.ResolvedInterval(), defaultInterval; got != want {
		t.Errorf("interval = %v, want built-in default %v", got, want)
	}
	if got, want := tg.ResolvedTimeout(), defaultTimeout; got != want {
		t.Errorf("timeout = %v, want built-in default %v", got, want)
	}
	if got, want := tg.HTTP.Method, "GET"; got != want {
		t.Errorf("method = %q, want %q", got, want)
	}
	if got, want := tg.HTTP.ResolvedMaxBodyBytes(), DefaultMaxBodyBytes; got != want {
		t.Errorf("max_body_bytes = %d, want %d", got, want)
	}
	if got, want := tg.HTTP.ResolvedMaxRedirects(), defaultMaxRedirects; got != want {
		t.Errorf("max_redirects = %d, want %d", got, want)
	}
	if !tg.HTTP.ResolvedFollowRedirects() {
		t.Error("follow_redirects = false, want default true")
	}
	if got, want := tg.HTTP.Expect.ExpectedStatus(), 200; got != want {
		t.Errorf("expected status = %d, want %d", got, want)
	}
}

func TestDefaultsMergeAndOverride(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
defaults:
  interval: 30s
  timeout: 5s
  http:
    method: HEAD
    max_redirects: 3
    follow_redirects: false
targets:
  - name: inherits-all
    http:
      url: https://a.example
  - name: overrides
    interval: 10s
    http:
      url: https://b.example
      method: GET
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	inherits := cfg.Targets[0]
	if got, want := inherits.ResolvedInterval(), 30*time.Second; got != want {
		t.Errorf("inherited interval = %v, want %v", got, want)
	}
	if got, want := inherits.ResolvedTimeout(), 5*time.Second; got != want {
		t.Errorf("inherited timeout = %v, want %v", got, want)
	}
	if got, want := inherits.HTTP.Method, "HEAD"; got != want {
		t.Errorf("inherited method = %q, want %q", got, want)
	}
	if got, want := inherits.HTTP.ResolvedMaxRedirects(), 3; got != want {
		t.Errorf("inherited max_redirects = %d, want %d", got, want)
	}
	if inherits.HTTP.ResolvedFollowRedirects() {
		t.Error("inherited follow_redirects = true, want false from defaults")
	}

	over := cfg.Targets[1]
	if got, want := over.ResolvedInterval(), 10*time.Second; got != want {
		t.Errorf("overridden interval = %v, want %v", got, want)
	}
	if got, want := over.ResolvedTimeout(), 5*time.Second; got != want {
		t.Errorf("overridden target timeout = %v, want inherited %v", got, want)
	}
	if got, want := over.HTTP.Method, "GET"; got != want {
		t.Errorf("overridden method = %q, want %q", got, want)
	}
}

func TestMaxBodyBytesOverrideAndOptOut(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
defaults:
  http:
    max_body_bytes: 1048576
targets:
  - name: inherits
    http:
      url: https://a.example
  - name: raises
    http:
      url: https://b.example
      max_body_bytes: 5242880
  - name: uncapped
    http:
      url: https://c.example
      max_body_bytes: 0
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := cfg.Targets[0].HTTP.ResolvedMaxBodyBytes(), int64(1048576); got != want {
		t.Errorf("inherited max_body_bytes = %d, want %d", got, want)
	}
	// Per-target override to a larger cap.
	if got, want := cfg.Targets[1].HTTP.ResolvedMaxBodyBytes(), int64(5242880); got != want {
		t.Errorf("raised max_body_bytes = %d, want %d", got, want)
	}
	// Explicit 0 opts out of the cap and is preserved over the 1 MiB default.
	if got := cfg.Targets[2].HTTP.ResolvedMaxBodyBytes(); got != 0 {
		t.Errorf("uncapped max_body_bytes = %d, want 0 (opt-out preserved over the default)", got)
	}
}

func TestValidationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name:    "no targets",
			yaml:    "defaults:\n  interval: 30s\n",
			wantSub: "no targets defined",
		},
		{
			name:    "missing name",
			yaml:    "targets:\n  - http:\n      url: https://a.example\n",
			wantSub: "missing name",
		},
		{
			name:    "duplicate name",
			yaml:    "targets:\n  - name: dup\n    http:\n      url: https://a.example\n  - name: dup\n    http:\n      url: https://b.example\n",
			wantSub: `duplicate target name "dup"`,
		},
		{
			name:    "no http block",
			yaml:    "targets:\n  - name: x\n",
			wantSub: "no protocol block",
		},
		{
			name:    "missing url",
			yaml:    "targets:\n  - name: x\n    http:\n      method: GET\n",
			wantSub: "http.url is required",
		},
		{
			name:    "bad scheme",
			yaml:    "targets:\n  - name: x\n    http:\n      url: ftp://a.example\n",
			wantSub: "scheme must be http or https",
		},
		{
			name:    "bad method",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      method: POST\n",
			wantSub: "http.method must be GET or HEAD",
		},
		{
			name:    "status out of range",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      expect:\n        status: 42\n",
			wantSub: "out of range",
		},
		{
			name:    "bad regex",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      expect:\n        body_regex:\n          - \"(\"\n",
			wantSub: "does not compile",
		},
		{
			name:    "disallowed tag",
			yaml:    "targets:\n  - name: x\n    tags:\n      team: platform\n    http:\n      url: https://a.example\n",
			wantSub: "are not allowed",
		},
		{
			name:    "negative interval override",
			yaml:    "targets:\n  - name: x\n    interval: -5s\n    http:\n      url: https://a.example\n",
			wantSub: "interval must be greater than zero",
		},
		{
			name:    "negative max_body_bytes",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      max_body_bytes: -1\n",
			wantSub: "max_body_bytes must not be negative",
		},
		{
			name:    "no-cap opt-out in defaults",
			yaml:    "defaults:\n  http:\n    max_body_bytes: 0\ntargets:\n  - name: x\n    http:\n      url: https://a.example\n",
			wantSub: "only allowed per target",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseResolve(t, tc.yaml)
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte("targets:\n  - name: x\n    http:\n      url: https://a.example\n      expect:\n        status_codee: 200\n"))
	if err == nil {
		t.Fatal("expected unknown-field error, got nil")
	}
	if !strings.Contains(err.Error(), "status_codee") {
		t.Fatalf("error %q does not mention the unknown field", err.Error())
	}
}

func TestInvalidDurationString(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte("defaults:\n  interval: not-a-duration\ntargets: []\n"))
	if err == nil {
		t.Fatal("expected duration parse error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid duration") {
		t.Fatalf("error %q does not describe the bad duration", err.Error())
	}
}

func TestValidationCollectsMultipleErrors(t *testing.T) {
	t.Parallel()

	// Two distinct problems: bad method and disallowed tag on the same target.
	_, err := parseResolve(t, `
targets:
  - name: x
    tags:
      team: platform
    http:
      url: https://a.example
      method: POST
`)
	if err == nil {
		t.Fatal("expected errors, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "http.method") || !strings.Contains(msg, "are not allowed") {
		t.Fatalf("expected both method and tag errors, got: %q", msg)
	}
}

func TestLoadFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "targets:\n  - name: homepage\n    interval: 15s\n    http:\n      url: https://example.org\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got, want := cfg.Targets[0].ResolvedInterval(), 15*time.Second; got != want {
		t.Errorf("interval = %v, want %v", got, want)
	}
}

func TestLoadMissingFile(t *testing.T) {
	t.Parallel()

	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
