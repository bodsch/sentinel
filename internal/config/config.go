// Package config loads, validates and resolves Sentinel's YAML configuration.
//
// The 0.1 configuration surface is intentionally small: a global `defaults`
// block and a list of `targets`, with no templates. Defaults are merged into
// each target with a trivial rule — a value set on the target wins, otherwise
// the default applies (no deep merge). Only the HTTP protocol is supported.
//
// Validation checks structure, schema and semantics only; it never checks
// reachability. Whether a target host resolves or responds is a runtime
// measurement, so an unreachable target is never a configuration error.
package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultMaxBodyBytes is the fallback cap on the number of response body bytes a
// probe reads. It bounds memory use and is a denial-of-service safeguard.
const DefaultMaxBodyBytes int64 = 1 << 20 // 1 MiB

// Built-in defaults applied when neither the target nor the defaults block set a
// value.
const (
	defaultInterval     = 60 * time.Second
	defaultTimeout      = 10 * time.Second
	defaultMethod       = "GET"
	defaultMaxRedirects = 10
	defaultDNSType      = "A"
)

// AllowedDNSTypes is the set of DNS record types supported in 0.2.
var AllowedDNSTypes = map[string]struct{}{
	"A":    {},
	"AAAA": {},
	"MX":   {},
	"TXT":  {},
}

// AllowedLabelTags is the fixed set of target tag keys that may become Prometheus
// labels. Any tag outside this set is rejected during validation to prevent
// accidental high-cardinality labels. (The always-present "target" and "type"
// labels are added by the metrics layer, not by tags.)
var AllowedLabelTags = map[string]struct{}{
	"environment": {},
	"location":    {},
	"service":     {},
}

// Config is the top-level configuration document.
type Config struct {
	Defaults Defaults `yaml:"defaults"`
	Targets  []Target `yaml:"targets"`
}

// Defaults holds settings inherited by every target unless the target overrides
// them. Pointer fields distinguish "unset" (nil) from an explicit value, so an
// explicit non-positive duration is rejected during validation rather than being
// mistaken for unset and silently replaced by a built-in default.
type Defaults struct {
	Interval *Duration    `yaml:"interval"`
	Timeout  *Duration    `yaml:"timeout"`
	HTTP     HTTPDefaults `yaml:"http"`
}

// HTTPDefaults holds HTTP settings that targets inherit. Pointer fields
// distinguish "unset" (nil) from an explicit value, so a target can override a
// true default with false.
type HTTPDefaults struct {
	Method          string `yaml:"method"`
	FollowRedirects *bool  `yaml:"follow_redirects"`
	MaxRedirects    *int   `yaml:"max_redirects"`
	MaxBodyBytes    *int64 `yaml:"max_body_bytes"`
}

// Target is one monitored endpoint. Exactly one protocol block must be present
// (HTTP or DNS).
//
// Interval and Timeout are pointers so an explicitly configured non-positive
// value can be told apart from "unset". The effective values, after merging
// defaults, are exposed via ResolvedInterval and ResolvedTimeout.
type Target struct {
	Name     string            `yaml:"name"`
	Interval *Duration         `yaml:"interval"`
	Timeout  *Duration         `yaml:"timeout"`
	Tags     map[string]string `yaml:"tags"`
	HTTP     *HTTPConfig       `yaml:"http"`
	DNS      *DNSConfig        `yaml:"dns"`
	TCP      *TCPConfig        `yaml:"tcp"`

	// resolved effective values, filled by applyDefaults.
	resolvedInterval time.Duration
	resolvedTimeout  time.Duration
}

// ResolvedInterval returns the effective probe interval after defaults are
// merged. Valid only after the config has been loaded (or applyDefaults run).
func (t *Target) ResolvedInterval() time.Duration { return t.resolvedInterval }

// ResolvedTimeout returns the effective total timeout after defaults are merged.
// Valid only after the config has been loaded (or applyDefaults run).
func (t *Target) ResolvedTimeout() time.Duration { return t.resolvedTimeout }

// HTTPConfig describes an HTTP/HTTPS check. After Load, all fields are resolved
// (defaults merged in) and ready to use.
type HTTPConfig struct {
	URL             string `yaml:"url"`
	Method          string `yaml:"method"`
	FollowRedirects *bool  `yaml:"follow_redirects"`
	MaxRedirects    *int   `yaml:"max_redirects"`
	MaxBodyBytes    *int64 `yaml:"max_body_bytes"`
	// Headers are request headers sent with the probe (distinct from
	// Expect.Headers, which validate the response). "Host" sets the request host.
	// For security they are sent only to the target's own host, not carried across
	// a redirect to a different host.
	Headers map[string]string `yaml:"headers"`
	// BasicAuth adds an HTTP Basic Authorization header. Mutually exclusive with
	// BearerToken and an explicit Authorization request header.
	BasicAuth *BasicAuth `yaml:"basic_auth"`
	// BearerToken adds an "Authorization: Bearer <token>" header.
	BearerToken string `yaml:"bearer_token"`
	// Body is the request body sent with the initial request (typically with
	// POST/PUT/PATCH). Set its Content-Type via Headers. Redirects are followed
	// as GET without a body.
	Body   string `yaml:"body"`
	Expect Expect `yaml:"expect"`
}

// BasicAuth holds HTTP Basic credentials. The password may be empty; the username
// is required when the block is present.
type BasicAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Expect declares the response validations a target must satisfy. A zero Status
// means "expect 200".
type Expect struct {
	Status    int               `yaml:"status"`
	BodyRegex []string          `yaml:"body_regex"`
	Headers   map[string]string `yaml:"headers"`
}

// DNSConfig describes a DNS check: a query of a given type against a given
// resolver, optionally validated against expected answers.
type DNSConfig struct {
	// Server is the resolver to query, "host" or "host:port" (default port 53).
	Server string `yaml:"server"`
	// Query is the name to look up (e.g. "example.org").
	Query string `yaml:"query"`
	// Type is the record type: A, AAAA, MX or TXT. Defaults to A.
	Type string `yaml:"type"`
	// Expected is an optional set of expected answer strings. When set, at least
	// one answer must match one expected value.
	Expected []string `yaml:"expected"`
}

// TCPConfig describes a TCP connection check: establish a connection to Address
// and, optionally, read a banner and validate it against regex patterns.
type TCPConfig struct {
	// Address is the "host:port" to connect to.
	Address string `yaml:"address"`
	// Expect optionally validates a banner the server sends on connect.
	Expect TCPExpect `yaml:"expect"`
}

// TCPExpect declares TCP response validations.
type TCPExpect struct {
	// BannerRegex are patterns the server's banner must all match. When set, the
	// probe reads a banner after connecting; when empty, the probe only checks
	// that a connection can be established.
	BannerRegex []string `yaml:"banner_regex"`
}

// Duration is a time.Duration that unmarshals from a Go duration string such as
// "30s" or "5m".
type Duration time.Duration

// UnmarshalYAML decodes a duration string into a Duration.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"30s\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Duration returns the value as a time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// ResolvedFollowRedirects reports the effective follow-redirects setting,
// defaulting to true when unset.
func (h *HTTPConfig) ResolvedFollowRedirects() bool {
	if h.FollowRedirects == nil {
		return true
	}
	return *h.FollowRedirects
}

// ResolvedMaxRedirects reports the effective maximum redirect count, defaulting
// to defaultMaxRedirects when unset.
func (h *HTTPConfig) ResolvedMaxRedirects() int {
	if h.MaxRedirects == nil {
		return defaultMaxRedirects
	}
	return *h.MaxRedirects
}

// ResolvedMaxBodyBytes reports the effective body-size cap in bytes. When unset
// (nil) it defaults to DefaultMaxBodyBytes. An explicit value is returned as-is,
// including an explicit 0, which the probe interprets as "no cap" — read the
// full body, bounded only by the per-target timeout. This distinguishes "unset"
// (nil, → 1 MiB default) from an explicit opt-out (0).
func (h *HTTPConfig) ResolvedMaxBodyBytes() int64 {
	if h.MaxBodyBytes == nil {
		return DefaultMaxBodyBytes
	}
	return *h.MaxBodyBytes
}

// ExpectedStatus reports the effective expected status code, defaulting to 200.
func (e Expect) ExpectedStatus() int {
	if e.Status == 0 {
		return 200
	}
	return e.Status
}
