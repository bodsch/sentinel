package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Validate checks the resolved configuration for structural and semantic errors.
// It accumulates every problem and returns them joined, so a single --validate
// run surfaces all issues at once rather than one at a time.
//
// Validation never checks reachability: an unreachable or unresolvable host is a
// runtime measurement, not a configuration error.
func (c *Config) Validate() error {
	var errs []error

	if len(c.Targets) == 0 {
		errs = append(errs, errors.New("config: no targets defined"))
	}

	seen := make(map[string]struct{}, len(c.Targets))
	for i := range c.Targets {
		t := &c.Targets[i]

		name := strings.TrimSpace(t.Name)
		if name == "" {
			errs = append(errs, fmt.Errorf("config: target #%d: missing name", i+1))
			// Without a name, further messages can't be attributed meaningfully,
			// but we still validate its fields below under a placeholder.
		} else {
			if _, dup := seen[name]; dup {
				errs = append(errs, fmt.Errorf("config: duplicate target name %q", name))
			}
			seen[name] = struct{}{}
		}

		errs = append(errs, validateTarget(t)...)
	}

	return errors.Join(errs...)
}

// validateTarget validates a single resolved target and returns any errors.
func validateTarget(t *Target) []error {
	var errs []error
	label := targetLabel(t)

	if t.resolvedInterval <= 0 {
		errs = append(errs, fmt.Errorf("config: %s: interval must be greater than zero", label))
	}
	if t.resolvedTimeout <= 0 {
		errs = append(errs, fmt.Errorf("config: %s: timeout must be greater than zero", label))
	}

	// Exactly one protocol block must be present.
	protocols := 0
	if t.HTTP != nil {
		protocols++
	}
	if t.DNS != nil {
		protocols++
	}
	switch {
	case protocols == 0:
		errs = append(errs, fmt.Errorf("config: %s: no protocol block (exactly one of \"http\", \"dns\" is required)", label))
	case protocols > 1:
		errs = append(errs, fmt.Errorf("config: %s: multiple protocol blocks (exactly one of \"http\", \"dns\" is allowed)", label))
	}

	if t.HTTP != nil {
		errs = append(errs, validateHTTP(label, t.HTTP)...)
	}
	if t.DNS != nil {
		errs = append(errs, validateDNS(label, t.DNS)...)
	}

	errs = append(errs, validateTags(label, t.Tags)...)
	return errs
}

// validateDNS validates a resolved DNS block.
func validateDNS(label string, d *DNSConfig) []error {
	var errs []error

	if strings.TrimSpace(d.Server) == "" {
		errs = append(errs, fmt.Errorf("config: %s: dns.server is required", label))
	} else if !validDNSServer(d.Server) {
		errs = append(errs, fmt.Errorf("config: %s: dns.server %q is not a valid host or host:port", label, d.Server))
	}

	if strings.TrimSpace(d.Query) == "" {
		errs = append(errs, fmt.Errorf("config: %s: dns.query is required", label))
	}

	if _, ok := AllowedDNSTypes[d.Type]; !ok {
		errs = append(errs, fmt.Errorf("config: %s: dns.type %q is not supported (allowed: %s)", label, d.Type, allowedDNSTypesList()))
	}

	for _, e := range d.Expected {
		if strings.TrimSpace(e) == "" {
			errs = append(errs, fmt.Errorf("config: %s: dns.expected must not contain empty values", label))
			break
		}
	}

	return errs
}

// validDNSServer reports whether s is a bare host or a host:port. It rejects
// obvious mistakes such as an embedded scheme ("http://…"), whitespace, a
// non-numeric port, or a colon-bearing host that is not a valid IPv6 literal.
func validDNSServer(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t\r\n/") {
		return false
	}
	// host:port (or [ipv6]:port) — the host must be non-empty and the port a
	// valid number.
	if host, port, err := net.SplitHostPort(s); err == nil {
		if host == "" {
			return false
		}
		p, err := strconv.Atoi(port)
		return err == nil && p >= 1 && p <= 65535
	}
	// No host:port. A colon here means it must be a bare IPv6 literal.
	if strings.Contains(s, ":") {
		return net.ParseIP(s) != nil
	}
	// Otherwise a bare host or IPv4 literal.
	return true
}

// allowedDNSTypesList returns the allowed DNS types as a sorted, comma-separated
// string for error messages.
func allowedDNSTypesList() string {
	keys := make([]string, 0, len(AllowedDNSTypes))
	for k := range AllowedDNSTypes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// validateHTTP validates a resolved HTTP block.
func validateHTTP(label string, h *HTTPConfig) []error {
	var errs []error

	if strings.TrimSpace(h.URL) == "" {
		errs = append(errs, fmt.Errorf("config: %s: http.url is required", label))
	} else if u, err := url.Parse(h.URL); err != nil {
		errs = append(errs, fmt.Errorf("config: %s: http.url is not a valid URL: %v", label, err))
	} else {
		switch u.Scheme {
		case "http", "https":
			// ok
		default:
			errs = append(errs, fmt.Errorf("config: %s: http.url scheme must be http or https, got %q", label, u.Scheme))
		}
		if u.Host == "" {
			errs = append(errs, fmt.Errorf("config: %s: http.url must include a host", label))
		}
		// 0.1 has no authentication support; credentials embedded in the URL
		// cannot be used and would leak into logs. Reject them.
		if u.User != nil {
			errs = append(errs, fmt.Errorf("config: %s: http.url must not embed credentials (userinfo)", label))
		}
	}

	switch h.Method {
	case "GET", "HEAD":
		// ok (0.1 supports GET and HEAD)
	default:
		errs = append(errs, fmt.Errorf("config: %s: http.method must be GET or HEAD in 0.1, got %q", label, h.Method))
	}

	if h.ResolvedMaxRedirects() < 0 {
		errs = append(errs, fmt.Errorf("config: %s: http.max_redirects must not be negative", label))
	}
	if h.ResolvedMaxBodyBytes() <= 0 {
		errs = append(errs, fmt.Errorf("config: %s: http.max_body_bytes must be greater than zero", label))
	}

	if h.Expect.Status != 0 && (h.Expect.Status < 100 || h.Expect.Status > 599) {
		errs = append(errs, fmt.Errorf("config: %s: http.expect.status %d is out of range (100-599)", label, h.Expect.Status))
	}

	for _, pattern := range h.Expect.BodyRegex {
		if strings.TrimSpace(pattern) == "" {
			// An empty pattern matches everything and is a silent no-op — reject
			// it rather than accepting a useless validator.
			errs = append(errs, fmt.Errorf("config: %s: http.expect.body_regex must not be empty", label))
			continue
		}
		if _, err := regexp.Compile(pattern); err != nil {
			errs = append(errs, fmt.Errorf("config: %s: http.expect.body_regex %q does not compile: %v", label, pattern, err))
		}
	}

	return errs
}

// validateTags rejects any tag key outside the fixed allowed label set, and any
// allowed tag whose value is empty (empty label values are the same label-hygiene
// problem the allow-list exists to prevent).
func validateTags(label string, tags map[string]string) []error {
	if len(tags) == 0 {
		return nil
	}

	var errs []error
	var bad, empty []string
	for k, v := range tags {
		if _, ok := AllowedLabelTags[k]; !ok {
			bad = append(bad, k)
			continue
		}
		if strings.TrimSpace(v) == "" {
			empty = append(empty, k)
		}
	}

	if len(bad) > 0 {
		sort.Strings(bad)
		errs = append(errs, fmt.Errorf("config: %s: tags %v are not allowed (allowed: %s)", label, bad, allowedTagsList()))
	}
	if len(empty) > 0 {
		sort.Strings(empty)
		errs = append(errs, fmt.Errorf("config: %s: tags %v must not have empty values", label, empty))
	}
	return errs
}

// targetLabel produces a stable human reference for a target in error messages.
func targetLabel(t *Target) string {
	if name := strings.TrimSpace(t.Name); name != "" {
		return fmt.Sprintf("target %q", name)
	}
	return "unnamed target"
}

// allowedTagsList returns the allowed tag keys as a sorted, comma-separated
// string for error messages.
func allowedTagsList() string {
	keys := make([]string, 0, len(AllowedLabelTags))
	for k := range AllowedLabelTags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
