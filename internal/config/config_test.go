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

func TestHTTPRequestHeadersAndAuthValid(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
targets:
  - name: with-headers-and-basic
    http:
      url: https://a.example
      headers:
        X-Api-Key: abc
        Host: vhost.example
      basic_auth:
        username: alice
        password: s3cret
  - name: with-bearer
    http:
      url: https://b.example
      bearer_token: tok
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	a := cfg.Targets[0].HTTP
	if a.Headers["X-Api-Key"] != "abc" || a.Headers["Host"] != "vhost.example" {
		t.Errorf("request headers = %v, want X-Api-Key/Host set", a.Headers)
	}
	if a.BasicAuth == nil || a.BasicAuth.Username != "alice" || a.BasicAuth.Password != "s3cret" {
		t.Errorf("basic_auth = %+v, want alice/s3cret", a.BasicAuth)
	}
	if b := cfg.Targets[1].HTTP; b.BearerToken != "tok" {
		t.Errorf("bearer_token = %q, want tok", b.BearerToken)
	}
}

func TestHTTPMethodAndBodyValid(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
targets:
  - name: post
    http:
      url: https://a.example
      method: post
      body: '{"k":"v"}'
      headers:
        Content-Type: application/json
  - name: delete
    http:
      url: https://b.example
      method: DELETE
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p := cfg.Targets[0].HTTP; p.Method != "POST" || p.Body != `{"k":"v"}` {
		t.Errorf("post target: method=%q body=%q, want POST + json body", p.Method, p.Body)
	}
	if d := cfg.Targets[1].HTTP; d.Method != "DELETE" {
		t.Errorf("delete target: method=%q, want DELETE", d.Method)
	}
}

func TestTCPValid(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
targets:
  - name: ssh
    tcp:
      address: example.com:22
      expect:
        banner_regex:
          - "^SSH-2.0"
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tc := cfg.Targets[0].TCP
	if tc == nil || tc.Address != "example.com:22" {
		t.Fatalf("tcp block = %+v, want address example.com:22", tc)
	}
	if len(tc.Expect.BannerRegex) != 1 || tc.Expect.BannerRegex[0] != "^SSH-2.0" {
		t.Errorf("banner_regex = %v, want [^SSH-2.0]", tc.Expect.BannerRegex)
	}
}

func TestHTTPJSONExpectValid(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
targets:
  - name: api
    http:
      url: https://a.example
      expect:
        json:
          - path: "$.status"
            equals: "ok"
          - path: "$.data.items"
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	j := cfg.Targets[0].HTTP.Expect.JSON
	if len(j) != 2 {
		t.Fatalf("json checks = %d, want 2", len(j))
	}
	if j[0].Path != "$.status" || j[0].Equals == nil || *j[0].Equals != "ok" {
		t.Errorf("check[0] = %+v, want $.status equals ok", j[0])
	}
	if j[1].Path != "$.data.items" || j[1].Equals != nil {
		t.Errorf("check[1] = %+v, want $.data.items existence-only", j[1])
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
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      method: TRACE\n",
			wantSub: "http.method must be one of",
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
		{
			name:    "basic_auth without username",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      basic_auth:\n        password: p\n",
			wantSub: "basic_auth.username is required",
		},
		{
			name:    "basic_auth and bearer_token both set",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      bearer_token: t\n      basic_auth:\n        username: u\n        password: p\n",
			wantSub: "at most one of",
		},
		{
			name:    "auth header and bearer_token both set",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      bearer_token: t\n      headers:\n        Authorization: Bearer other\n",
			wantSub: "at most one of",
		},
		{
			name:    "empty request header name",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      headers:\n        \"\": v\n",
			wantSub: "empty header name",
		},
		{
			name:    "body with GET",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      method: GET\n      body: hi\n",
			wantSub: "http.body is not allowed with method GET",
		},
		{
			name:    "tcp missing address",
			yaml:    "targets:\n  - name: x\n    tcp:\n      expect:\n        banner_regex: [\"^SSH\"]\n",
			wantSub: "tcp.address is required",
		},
		{
			name:    "tcp address without port",
			yaml:    "targets:\n  - name: x\n    tcp:\n      address: example.com\n",
			wantSub: "must be host:port",
		},
		{
			name:    "tcp non-numeric port",
			yaml:    "targets:\n  - name: x\n    tcp:\n      address: example.com:ssh\n",
			wantSub: "must be a number in 1-65535",
		},
		{
			name:    "tcp bad banner regex",
			yaml:    "targets:\n  - name: x\n    tcp:\n      address: example.com:22\n      expect:\n        banner_regex: [\"(\"]\n",
			wantSub: "does not compile",
		},
		{
			name:    "two protocol blocks",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n    tcp:\n      address: a.example:22\n",
			wantSub: "multiple protocol blocks",
		},
		{
			name:    "json expect without path",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      expect:\n        json:\n          - equals: ok\n",
			wantSub: "json[0].path is required",
		},
		{
			name:    "json expect invalid path",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      expect:\n        json:\n          - path: \"$[\"\n",
			wantSub: "not valid JSONPath",
		},
		{
			name:    "json expect with HEAD",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      method: HEAD\n      expect:\n        json:\n          - path: \"$.status\"\n",
			wantSub: "cannot be used with method HEAD",
		},
		{
			name:    "tls insecure and ca_file both set",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      tls:\n        insecure_skip_verify: true\n        ca_file: /etc/ca.pem\n",
			wantSub: "mutually exclusive",
		},
		{
			// Expectations describe a verified connection; combined with
			// skip-verify they would promise something the config cannot give.
			name:    "tls expect with insecure_skip_verify",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      tls:\n        insecure_skip_verify: true\n        expect:\n          min_days_remaining: 30\n",
			wantSub: "cannot be combined with http.tls.insecure_skip_verify",
		},
		{
			name:    "tls expect negative min_days_remaining",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      tls:\n        expect:\n          min_days_remaining: -1\n",
			wantSub: "min_days_remaining must not be negative",
		},
		{
			name:    "tls expect unsupported min_version",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      tls:\n        expect:\n          min_version: \"1.1\"\n",
			wantSub: "unsupported TLS version",
		},
		{
			name:    "tls expect invalid issuer_regex",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      tls:\n        expect:\n          issuer_regex: \"[\"\n",
			wantSub: "is not a valid regular expression",
		},
		{
			name:    "tls expect unknown field",
			yaml:    "targets:\n  - name: x\n    http:\n      url: https://a.example\n      tls:\n        expect:\n          forbid_weak_ciphers: true\n",
			wantSub: "forbid_weak_ciphers",
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
      method: TRACE
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

// TestTLSExpectParsed asserts a complete, valid tls.expect block round-trips
// through parsing and validation with every field preserved.
func TestTLSExpectParsed(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
targets:
  - name: homepage
    http:
      url: https://a.example
      tls:
        ca_file: /etc/sentinel/ca.pem
        expect:
          min_days_remaining: 21
          min_version: "1.3"
          require_ocsp_stapling: true
          issuer_regex: "Let's Encrypt"
`)
	if err != nil {
		t.Fatalf("valid tls.expect rejected: %v", err)
	}

	e := cfg.Targets[0].HTTP.TLS.Expect
	if e == nil {
		t.Fatal("tls.expect not parsed")
	}
	if e.MinDaysRemaining != 21 {
		t.Errorf("min_days_remaining = %d, want 21", e.MinDaysRemaining)
	}
	if e.MinVersion != "1.3" {
		t.Errorf("min_version = %q, want 1.3", e.MinVersion)
	}
	if !e.RequireOCSPStapling {
		t.Error("require_ocsp_stapling not parsed")
	}
	if e.IssuerRegex != "Let's Encrypt" {
		t.Errorf("issuer_regex = %q, unexpected", e.IssuerRegex)
	}
}

// TestTLSWithoutExpectStaysNil guards the promise that a target without the
// block enforces nothing new.
func TestTLSWithoutExpectStaysNil(t *testing.T) {
	t.Parallel()

	cfg, err := parseResolve(t, `
targets:
  - name: homepage
    http:
      url: https://a.example
`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tlsCfg := cfg.Targets[0].HTTP.TLS; tlsCfg != nil && tlsCfg.Expect != nil {
		t.Errorf("tls.expect = %+v, want nil without a tls block", tlsCfg.Expect)
	}
}
