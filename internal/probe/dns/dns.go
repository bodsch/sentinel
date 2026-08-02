// Package dns implements the DNS probe: it queries a configured resolver for a
// record and validates the response.
//
// It uses github.com/miekg/dns for full control over the query — a specific
// resolver, the record type, the response RCODE and the answer set — which the
// standard net.Resolver cannot provide (no RCODE, no custom server per query).
package dns

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	dnslib "github.com/miekg/dns"

	"bodsch.me/sentinel/internal/probe"
)

// ProbeType is the protocol identifier for DNS probes.
const ProbeType = "dns"

// defaultPort is the DNS port appended when the server has none.
const defaultPort = "53"

// typeCodes maps supported record-type names to their miekg/dns codes.
var typeCodes = map[string]uint16{
	"A":    dnslib.TypeA,
	"AAAA": dnslib.TypeAAAA,
	"MX":   dnslib.TypeMX,
	"TXT":  dnslib.TypeTXT,
}

// Options carries the fully-resolved settings for one DNS target.
type Options struct {
	// Name is the target name (for reference/logging).
	Name string
	// Server is the resolver, "host" or "host:port" (port defaults to 53).
	Server string
	// Query is the name to look up.
	Query string
	// Type is the record type: A, AAAA, MX or TXT (already uppercased).
	Type string
	// Expected is an optional set of expected answers; when set, at least one
	// answer must match one expected value.
	Expected []string
	// Timeout is the total per-run timeout.
	Timeout time.Duration
}

// udpBufferSize is the EDNS0-advertised UDP receive buffer. Advertising a large
// buffer lets resolvers return bigger answers over UDP before resorting to
// truncation.
const udpBufferSize = 4096

// Prober runs DNS checks for a single target. It satisfies probe.Prober.
type Prober struct {
	name      string
	server    string
	query     string
	qtype     uint16
	expected  []string
	timeout   time.Duration
	udpClient *dnslib.Client
	tcpClient *dnslib.Client
}

var _ probe.Prober = (*Prober)(nil)

// New builds a Prober from resolved options.
func New(opts Options) (*Prober, error) {
	if opts.Timeout <= 0 {
		return nil, errors.New("dns probe: timeout must be greater than zero")
	}
	qtype, ok := typeCodes[strings.ToUpper(opts.Type)]
	if !ok {
		return nil, errors.New("dns probe: unsupported record type " + opts.Type)
	}
	if strings.TrimSpace(opts.Server) == "" {
		return nil, errors.New("dns probe: server is required")
	}
	if strings.TrimSpace(opts.Query) == "" {
		return nil, errors.New("dns probe: query is required")
	}

	return &Prober{
		name:      opts.Name,
		server:    withDefaultPort(opts.Server),
		query:     dnslib.Fqdn(opts.Query),
		qtype:     qtype,
		expected:  opts.Expected,
		timeout:   opts.Timeout,
		udpClient: &dnslib.Client{Net: "udp"},
		tcpClient: &dnslib.Client{Net: "tcp"},
	}, nil
}

// Type implements probe.Prober.
func (p *Prober) Type() string { return ProbeType }

// Probe implements probe.Prober. It performs the query under the target's total
// timeout and classifies the outcome. It never returns an error: a failed check
// is a successful execution with Success=false.
func (p *Prober) Probe(ctx context.Context) probe.Result {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	msg := new(dnslib.Msg)
	msg.SetQuestion(p.query, p.qtype)
	// Advertise a larger UDP buffer so moderate answer sets arrive without
	// truncation.
	msg.SetEdns0(udpBufferSize, false)

	start := time.Now()
	resp, _, err := p.udpClient.ExchangeContext(ctx, msg, p.server)
	// On truncation (TC bit), retry over TCP so the answer set is complete —
	// otherwise answer_count is undercounted and expected-matching may miss a
	// record that was dropped from the truncated UDP response.
	truncated := false
	if err == nil && resp != nil && resp.Truncated {
		truncated = true
		resp, _, err = p.tcpClient.ExchangeContext(ctx, msg, p.server)
	}
	end := time.Now()

	res := probe.Result{
		Duration:  end.Sub(start),
		Timestamp: end,
	}
	res.Timings.DNS = res.Duration // the whole probe is the DNS query

	if err != nil {
		res.FailureReason = classifyError(err)
		return res
	}

	diag := &Diagnostics{
		ResponseCode:     resp.Rcode,
		ResponseCodeText: dnslib.RcodeToString[resp.Rcode],
		Answers:          extractAnswers(resp, p.qtype),
		Truncated:        truncated && resp.Truncated, // true only if TCP was also truncated
	}
	diag.AnswerCount = len(diag.Answers)
	res.Diagnostics = diag

	if resp.Rcode != dnslib.RcodeSuccess {
		res.FailureReason = probe.ReasonDNSError
		return res
	}

	// Without an expected set, a NOERROR response is a success even with zero
	// answers; the answer_count metric surfaces "did not resolve" for alerting.
	// With an expected set, at least one answer must match.
	if len(p.expected) > 0 && !matchExpected(diag.Answers, p.expected, p.qtype) {
		res.FailureReason = probe.ReasonValidationFailed
		return res
	}

	res.Success = true
	return res
}

// classifyError maps a query error to a stable FailureReason.
func classifyError(err error) probe.FailureReason {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return probe.ReasonTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return probe.ReasonTimeout
	}
	return probe.ReasonDNSError
}

// extractAnswers returns the answer values matching the queried type, with
// trailing dots trimmed for stable comparison and display.
func extractAnswers(resp *dnslib.Msg, qtype uint16) []string {
	var out []string
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype != qtype {
			continue
		}
		switch v := rr.(type) {
		case *dnslib.A:
			out = append(out, v.A.String())
		case *dnslib.AAAA:
			out = append(out, v.AAAA.String())
		case *dnslib.MX:
			out = append(out, strings.TrimSuffix(v.Mx, "."))
		case *dnslib.TXT:
			out = append(out, strings.Join(v.Txt, ""))
		}
	}
	return out
}

// matchExpected reports whether any answer matches any expected value, using a
// comparison appropriate to the record type:
//   - A/AAAA: parse both sides as IPs and compare numerically, so equivalent
//     textual forms (uppercase or expanded IPv6) still match.
//   - MX: hostnames are case-insensitive (RFC 4343); compare case-folded.
//   - TXT: text is case-sensitive; compare exactly.
func matchExpected(answers, expected []string, qtype uint16) bool {
	for _, a := range answers {
		for _, e := range expected {
			if valueEqual(a, strings.TrimSpace(e), qtype) {
				return true
			}
		}
	}
	return false
}

// valueEqual compares a single answer with a single expected value per type.
func valueEqual(answer, expected string, qtype uint16) bool {
	switch qtype {
	case dnslib.TypeA, dnslib.TypeAAAA:
		ia, ib := net.ParseIP(answer), net.ParseIP(expected)
		if ia != nil && ib != nil {
			return ia.Equal(ib)
		}
		return answer == expected
	case dnslib.TypeMX:
		return strings.EqualFold(strings.TrimSuffix(answer, "."), strings.TrimSuffix(expected, "."))
	default: // TXT and any other text-valued type: case-sensitive.
		return answer == expected
	}
}

// withDefaultPort appends the default DNS port when the server has none.
func withDefaultPort(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, defaultPort)
}
