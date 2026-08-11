// Package tcp implements the TCP probe: it establishes a TCP connection to a
// configured address and, optionally, reads a banner and validates it against
// regex patterns. It measures the connection-establishment time.
package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// ProbeType is the protocol identifier for TCP probes.
const ProbeType = "tcp"

// maxBannerBytes caps how many banner bytes are read from the connection. It
// bounds memory and is a denial-of-service safeguard against an endless stream.
const maxBannerBytes = 4096

// Options carries the fully-resolved settings for one TCP target.
type Options struct {
	// Name is the target name (for reference/logging).
	Name string
	// Address is the "host:port" to connect to.
	Address string
	// BannerRegex, when non-empty, causes the probe to read a banner after
	// connecting and require it to match every pattern.
	BannerRegex []string
	// Timeout is the total per-run timeout (connect plus any banner read).
	Timeout time.Duration
}

// Prober runs TCP checks for a single target. It satisfies probe.Prober.
type Prober struct {
	name        string
	address     string
	bannerRegex []*regexp.Regexp
	timeout     time.Duration
}

var _ probe.Prober = (*Prober)(nil)

// New builds a Prober from resolved options. It returns an error for an invalid
// timeout, an empty address, or a banner regex that fails to compile
// (configuration validation compiles them once already, so this is defensive).
func New(opts Options) (*Prober, error) {
	if opts.Timeout <= 0 {
		return nil, errors.New("tcp probe: timeout must be greater than zero")
	}
	if strings.TrimSpace(opts.Address) == "" {
		return nil, errors.New("tcp probe: address is required")
	}
	patterns := make([]*regexp.Regexp, 0, len(opts.BannerRegex))
	for _, p := range opts.BannerRegex {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("tcp probe: banner regex %q: %w", p, err)
		}
		patterns = append(patterns, re)
	}
	return &Prober{
		name:        opts.Name,
		address:     strings.TrimSpace(opts.Address),
		bannerRegex: patterns,
		timeout:     opts.Timeout,
	}, nil
}

// Type implements probe.Prober.
func (p *Prober) Type() string { return ProbeType }

// Probe implements probe.Prober. It connects under the target's total timeout,
// optionally validates a banner, and returns a typed Result. It never returns an
// error: a failed check is a successful execution with Success=false.
func (p *Prober) Probe(ctx context.Context) probe.Result {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	start := time.Now()
	diag, timings, reason := p.dial(ctx)
	end := time.Now()

	return probe.Result{
		Success:       reason == probe.ReasonNone,
		FailureReason: reason,
		Duration:      end.Sub(start),
		Timings:       timings,
		Diagnostics:   diag,
		Timestamp:     end,
	}
}

// dial establishes the connection, records the connect timing, and optionally
// reads and validates the banner.
func (p *Prober) dial(ctx context.Context) (*Diagnostics, probe.Timings, probe.FailureReason) {
	var timings probe.Timings
	diag := &Diagnostics{}

	var d net.Dialer
	connectStart := time.Now()
	conn, err := d.DialContext(ctx, "tcp", p.address)
	timings.Connect = time.Since(connectStart)
	if err != nil {
		return diag, timings, classifyError(err)
	}
	defer func() { _ = conn.Close() }()

	if len(p.bannerRegex) == 0 {
		return diag, timings, probe.ReasonNone
	}

	// Bound the banner read by the probe deadline so a silent server cannot hang
	// the probe beyond its timeout.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(dl)
	}

	// A banner can arrive in several TCP segments (e.g. a multiline SMTP
	// greeting), so accumulate across reads and re-check after each one, matching
	// as soon as every pattern is satisfied — a single read would false-mismatch
	// on fragmentation.
	banner := make([]byte, 0, 512)
	for len(banner) < maxBannerBytes {
		buf := make([]byte, maxBannerBytes-len(banner))
		n, rerr := conn.Read(buf)
		if n > 0 {
			banner = append(banner, buf[:n]...)
			diag.Banner = string(banner)
			if p.bannerMatches(diag.Banner) {
				return diag, timings, probe.ReasonNone
			}
		}
		if rerr != nil {
			if len(banner) == 0 {
				// Nothing arrived: a connection-level failure (reset, close, or
				// timeout), not a banner mismatch — classify it accordingly.
				return diag, timings, classifyError(rerr)
			}
			// A banner was received but never matched before the stream ended or
			// the deadline hit.
			return diag, timings, probe.ReasonValidationFailed
		}
	}
	// Read the byte cap without matching.
	return diag, timings, probe.ReasonValidationFailed
}

// bannerMatches reports whether s matches every configured banner pattern.
func (p *Prober) bannerMatches(s string) bool {
	for _, re := range p.bannerRegex {
		if !re.MatchString(s) {
			return false
		}
	}
	return true
}

// classifyError maps a dial or read error to a stable FailureReason. It delegates
// to the shared classification so a given failure reports the same reason no
// matter which protocol observed it.
func classifyError(err error) probe.FailureReason {
	return probe.ClassifyNetworkError(err)
}
