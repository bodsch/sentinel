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
)

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

// Target is one monitored endpoint. In 0.1 exactly one protocol block (HTTP)
// must be present.
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
	Expect          Expect `yaml:"expect"`
}

// Expect declares the response validations a target must satisfy. A zero Status
// means "expect 200".
type Expect struct {
	Status    int               `yaml:"status"`
	BodyRegex []string          `yaml:"body_regex"`
	Headers   map[string]string `yaml:"headers"`
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

// ResolvedMaxBodyBytes reports the effective body-size cap, defaulting to
// DefaultMaxBodyBytes when unset.
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
