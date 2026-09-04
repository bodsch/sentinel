package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Load reads, parses, resolves and validates the configuration file at path.
//
// On success it returns a *Config whose targets have all defaults merged in and
// are ready to use. On failure it returns an error describing every problem
// found (parse errors, or one joined error covering all validation failures).
func Load(path string) (*Config, error) {
	//nolint:gosec // G304: the config path is an operator-supplied CLI/env argument, not attacker input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %q: %w", path, err)
	}

	cfg, err := Parse(data)
	if err != nil {
		// Parse has no notion of a path (it is also used on in-memory documents),
		// so name the file here. This error is the last thing an operator sees
		// before the process exits; without the path they cannot tell which of
		// several mounted or templated config files is at fault. The read error
		// above already names it, and the two must not disagree.
		return nil, fmt.Errorf("config: %q: %w", path, err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Parse decodes YAML into a Config without applying defaults or validating.
// Unknown fields are rejected so typos (e.g. "status_codee") fail loudly rather
// than being silently ignored. It is exported mainly for tests.
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		// An empty document (empty file, only comments, only whitespace) decodes
		// to io.EOF. Treat it as an empty config so Validate reports the clear
		// "no targets defined" instead of an opaque parse error.
		if errors.Is(err, io.EOF) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("config: parsing YAML: %w", err)
	}
	return &cfg, nil
}

// applyDefaults resolves every target's effective settings using the trivial
// rule: a value set on the target wins, otherwise the default applies, otherwise
// the built-in default. Interval/Timeout are resolved into the target's
// unexported resolved* fields; an explicit non-positive value is preserved (not
// replaced by a default) so Validate can reject it.
func (c *Config) applyDefaults() {
	for i := range c.Targets {
		t := &c.Targets[i]

		t.resolvedInterval = resolveDuration(t.Interval, c.Defaults.Interval, defaultInterval)
		t.resolvedTimeout = resolveDuration(t.Timeout, c.Defaults.Timeout, defaultTimeout)

		if t.HTTP != nil {
			applyHTTPDefaults(t.HTTP, c.Defaults.HTTP)
		}
		if t.DNS != nil {
			applyDNSDefaults(t.DNS)
		}
	}
}

// applyDNSDefaults normalises the record type (uppercase) and defaults it to A.
func applyDNSDefaults(d *DNSConfig) {
	if d.Type == "" {
		d.Type = defaultDNSType
	}
	d.Type = strings.ToUpper(d.Type)
}

// resolveDuration picks the effective duration: the target value if set,
// otherwise the default if set, otherwise the built-in. A set-but-non-positive
// value is returned as-is so validation can reject it.
func resolveDuration(target, def *Duration, builtin time.Duration) time.Duration {
	if target != nil {
		return target.Duration()
	}
	if def != nil {
		return def.Duration()
	}
	return builtin
}

// applyHTTPDefaults fills unset HTTP fields from the defaults block. Pointer
// values are cloned rather than aliased, so mutating a resolved field on one
// target cannot affect another target or the defaults block.
func applyHTTPDefaults(h *HTTPConfig, d HTTPDefaults) {
	if h.Method == "" {
		h.Method = d.Method
	}
	if h.Method == "" {
		h.Method = defaultMethod
	}
	h.Method = strings.ToUpper(h.Method)

	if h.FollowRedirects == nil {
		h.FollowRedirects = clonePtr(d.FollowRedirects)
	}
	if h.MaxRedirects == nil {
		h.MaxRedirects = clonePtr(d.MaxRedirects)
	}
	if h.MaxBodyBytes == nil {
		h.MaxBodyBytes = clonePtr(d.MaxBodyBytes)
	}
}

// clonePtr returns a pointer to a copy of *p, or nil if p is nil. It prevents
// pointer aliasing when defaults are shared across targets.
func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
