// Package dns implements the DNS probe: it queries one or more configured
// resolvers for a record and validates the responses.
//
// With several resolvers the probe compares them: every resolver must answer,
// and all of them must return the same answer set. That catches what a single
// resolver cannot show — a stale cache, a split-horizon leak, an unfinished
// propagation — while the per-resolver metrics say which one is off.
//
// It uses github.com/miekg/dns for full control over the query — a specific
// resolver, the record type, the response RCODE and the answer set — which the
// standard net.Resolver cannot provide (no RCODE, no custom server per query).
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
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
	"A":     dnslib.TypeA,
	"AAAA":  dnslib.TypeAAAA,
	"MX":    dnslib.TypeMX,
	"TXT":   dnslib.TypeTXT,
	"CNAME": dnslib.TypeCNAME,
	"SRV":   dnslib.TypeSRV,
}

// Options carries the fully-resolved settings for one DNS target.
type Options struct {
	// Name is the target name (for reference/logging).
	Name string
	// Servers are the resolvers to query, each "host" or "host:port" (port
	// defaults to 53). With more than one, their answers are compared.
	Servers []string
	// Query is the name to look up.
	Query string
	// Type is the record type: A, AAAA, MX, TXT, CNAME or SRV (already
	// uppercased).
	Type string
	// Expected is an optional set of expected answers; when set, at least one
	// answer must match one expected value.
	Expected []string
	// Timeout is the total per-run timeout.
	Timeout time.Duration
	// Authoritative switches to the delegation check: Query is a zone, the
	// first server is the resolver used to find its nameservers, and each
	// nameserver is asked directly for the zone's SOA. Type and Expected are
	// not used.
	Authoritative bool
	// Family selects the nameserver addresses queried in the authoritative
	// check; empty means FamilyIPv4.
	Family Family
	// DNSSEC requires every resolver to vouch for the answer with the AD flag:
	// queries carry the DO bit, and a response without AD fails with
	// dnssec_unvalidated. Not used by the authoritative check.
	DNSSEC bool
}

// udpBufferSize is the EDNS0-advertised UDP receive buffer. Advertising a large
// buffer lets resolvers return bigger answers over UDP before resorting to
// truncation.
const udpBufferSize = 4096

// Prober runs DNS checks for a single target. It satisfies probe.Prober.
type Prober struct {
	name      string
	servers   []string
	query     string
	qtype     uint16
	expected  []string
	timeout   time.Duration
	udpClient *dnslib.Client
	tcpClient *dnslib.Client

	authoritative bool
	family        Family
	dnssec        bool
	// nsTarget maps a nameserver address to the "ip:port" it is queried at.
	// Tests replace it to point at local servers.
	nsTarget func(netip.Addr) string
}

var _ probe.Prober = (*Prober)(nil)

// New builds a Prober from resolved options.
func New(opts Options) (*Prober, error) {
	if opts.Timeout <= 0 {
		return nil, errors.New("dns probe: timeout must be greater than zero")
	}
	qtype, ok := typeCodes[strings.ToUpper(opts.Type)]
	if opts.Authoritative {
		qtype, ok = dnslib.TypeSOA, true
	}
	if !ok {
		return nil, errors.New("dns probe: unsupported record type " + opts.Type)
	}
	family := opts.Family
	switch family {
	case "":
		family = FamilyIPv4
	case FamilyIPv4, FamilyIPv6, FamilyBoth:
	default:
		return nil, errors.New("dns probe: unsupported nameserver family " + string(opts.Family))
	}
	if len(opts.Servers) == 0 {
		return nil, errors.New("dns probe: at least one server is required")
	}
	servers := make([]string, 0, len(opts.Servers))
	for _, srv := range opts.Servers {
		if strings.TrimSpace(srv) == "" {
			return nil, errors.New("dns probe: server must not be empty")
		}
		servers = append(servers, withDefaultPort(strings.TrimSpace(srv)))
	}
	if strings.TrimSpace(opts.Query) == "" {
		return nil, errors.New("dns probe: query is required")
	}

	return &Prober{
		name:      opts.Name,
		servers:   servers,
		query:     dnslib.Fqdn(opts.Query),
		qtype:     qtype,
		expected:  opts.Expected,
		timeout:   opts.Timeout,
		udpClient: &dnslib.Client{Net: "udp"},
		tcpClient: &dnslib.Client{Net: "tcp"},

		authoritative: opts.Authoritative,
		family:        family,
		dnssec:        opts.DNSSEC && !opts.Authoritative,
		nsTarget:      defaultNSTarget,
	}, nil
}

// Type implements probe.Prober.
func (p *Prober) Type() string { return ProbeType }

// Probe implements probe.Prober. It queries every resolver concurrently under
// the target's total timeout and classifies the outcome. It never returns an
// error: a failed check is a successful execution with Success=false.
//
// The verdict is the first failure in this order: a resolver that could not be
// queried or answered with a non-NOERROR code (resolvers checked in configured
// order), with dnssec a response without the AD flag (dnssec_unvalidated), a
// resolver whose answers miss the expected set, answer sets that differ
// between resolvers (dns_mismatch).
func (p *Prober) Probe(ctx context.Context) probe.Result {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	if p.authoritative {
		return p.probeAuthoritative(ctx)
	}

	start := time.Now()
	results := make([]ResolverResult, len(p.servers))
	var wg sync.WaitGroup
	for i, server := range p.servers {
		wg.Go(func() { results[i] = p.exchange(ctx, server) })
	}
	wg.Wait()
	end := time.Now()

	res := probe.Result{
		Duration:  end.Sub(start),
		Timestamp: end,
	}
	// The whole probe is the DNS query; with several resolvers running in
	// parallel that is the slowest of them.
	res.Timings.DNS = res.Duration

	primary := results[0]
	if primary.err != nil && len(results) == 1 {
		// The only resolver produced no response at all, so there is nothing to
		// describe. With several resolvers the others still are.
		res.FailureReason = primary.Reason
		if res.FailureReason.IsTimeout() {
			// The whole probe is the query, so a timeout can only be here.
			res.TimeoutPhase = probe.PhaseDNS
		}
		return res
	}

	diag := &Diagnostics{
		ResponseCode:     primary.ResponseCode,
		ResponseCodeText: primary.ResponseCodeText,
		Answers:          primary.Answers,
		AnswerCount:      len(primary.Answers),
		Truncated:        primary.Truncated,
		Consistent:       true,
	}
	if p.dnssec {
		diag.DNSSEC = dnssecSummary(results)
	}
	if len(results) > 1 {
		diag.Resolvers = results
		diag.Consistent = sameAnswers(results, p.qtype)
	}
	res.Diagnostics = diag
	res.FailureReason = p.verdict(results, diag.Consistent)
	if res.FailureReason.IsTimeout() {
		res.TimeoutPhase = probe.PhaseDNS
	}
	res.Success = res.FailureReason == probe.ReasonNone
	return res
}

// verdict classifies the per-resolver results; see Probe for the order.
func (p *Prober) verdict(results []ResolverResult, consistent bool) probe.FailureReason {
	for _, r := range results {
		if r.Reason != probe.ReasonNone {
			return r.Reason
		}
	}
	// An answer nobody vouched for is not worth comparing: with dnssec set it
	// fails before its content is looked at.
	if p.dnssec {
		for _, r := range results {
			if !r.Authenticated {
				return probe.ReasonDNSSECUnvalidated
			}
		}
	}
	// Without an expected set, a NOERROR response is a success even with zero
	// answers; the answer_count metric surfaces "did not resolve" for alerting.
	// With an expected set, at least one answer of every resolver must match.
	if len(p.expected) > 0 {
		for _, r := range results {
			if !matchExpected(r.Answers, p.expected, p.qtype) {
				return probe.ReasonValidationFailed
			}
		}
	}
	if !consistent {
		return probe.ReasonDNSMismatch
	}
	return probe.ReasonNone
}

// exchange queries one resolver for the target's own question.
func (p *Prober) exchange(ctx context.Context, server string) ResolverResult {
	return p.exchangeType(ctx, server, p.query, p.qtype, true)
}

// exchangeType sends one query, falling back to TCP on a truncated UDP
// response.
//
// Parameters:
//   - ctx: carries the probe deadline.
//   - server: the server as "host:port".
//   - name: the fully-qualified name to ask for.
//   - qtype: the record type.
//   - recursion: whether to set the RD flag; off when asking an authoritative
//     server directly, so its own data is what answers.
//
// It returns the result; Reason is ReasonNone only for a NOERROR response.
func (p *Prober) exchangeType(ctx context.Context, server, name string, qtype uint16, recursion bool) ResolverResult {
	msg := new(dnslib.Msg)
	msg.SetQuestion(name, qtype)
	msg.RecursionDesired = recursion
	// Advertise a larger UDP buffer so moderate answer sets arrive without
	// truncation. With dnssec, the DO bit asks for the signatures and the AD
	// bit announces that the client understands it (RFC 6840 section 5.7), so
	// a validating resolver reports its verdict.
	msg.SetEdns0(udpBufferSize, p.dnssec && recursion)
	if p.dnssec && recursion {
		msg.AuthenticatedData = true
	}

	out := ResolverResult{Server: server}
	start := time.Now()
	resp, _, err := p.udpClient.ExchangeContext(ctx, msg, server)
	// On truncation (TC bit), retry over TCP so the answer set is complete —
	// otherwise answer_count is undercounted and expected-matching may miss a
	// record that was dropped from the truncated UDP response.
	truncated := false
	if err == nil && resp != nil && resp.Truncated {
		truncated = true
		resp, _, err = p.tcpClient.ExchangeContext(ctx, msg, server)
	}
	out.Duration = time.Since(start)

	if err != nil {
		out.err = err
		out.Reason = classifyError(err)
		return out
	}

	out.msg = resp
	out.ResponseCode = resp.Rcode
	out.ResponseCodeText = dnslib.RcodeToString[resp.Rcode]
	out.Answers = extractAnswers(resp, qtype)
	out.Authenticated = resp.AuthenticatedData
	out.SignatureExpiry = earliestSignatureExpiry(resp, qtype)
	out.Truncated = truncated && resp.Truncated // true only if TCP was also truncated
	if resp.Rcode != dnslib.RcodeSuccess {
		out.Reason = probe.ReasonDNSError
	}
	return out
}

// sameAnswers reports whether every resolver returned the same answer set. Sets
// are compared in canonical form, so order, duplicates, the case of host names
// and the spelling of IPv6 addresses do not count as a difference. A resolver
// without a response has no set to compare and is skipped: its failure is
// reported on its own.
func sameAnswers(results []ResolverResult, qtype uint16) bool {
	var want []string
	seen := false
	for _, r := range results {
		if r.err != nil {
			continue
		}
		set := canonicalSet(r.Answers, qtype)
		if !seen {
			want, seen = set, true
			continue
		}
		if !slices.Equal(set, want) {
			return false
		}
	}
	return true
}

// canonicalSet returns the sorted, de-duplicated canonical form of answers.
func canonicalSet(answers []string, qtype uint16) []string {
	out := make([]string, 0, len(answers))
	for _, a := range answers {
		out = append(out, canonical(a, qtype))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// canonical normalises one answer the same way valueEqual compares it.
func canonical(answer string, qtype uint16) string {
	switch qtype {
	case dnslib.TypeA, dnslib.TypeAAAA:
		if ip := net.ParseIP(answer); ip != nil {
			return ip.String()
		}
		return answer
	case dnslib.TypeMX, dnslib.TypeCNAME:
		return strings.ToLower(strings.TrimSuffix(answer, "."))
	case dnslib.TypeSRV:
		if v, ok := parseSRV(answer); ok {
			return fmt.Sprintf("%d %d %d %s", v.priority, v.weight, v.port, strings.ToLower(strings.TrimSuffix(v.target, ".")))
		}
		return answer
	default: // TXT: case-sensitive.
		return answer
	}
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
		case *dnslib.CNAME:
			out = append(out, strings.TrimSuffix(v.Target, "."))
		case *dnslib.SRV:
			out = append(out, fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, strings.TrimSuffix(v.Target, ".")))
		}
	}
	return out
}

// matchExpected reports whether any answer matches any expected value, using a
// comparison appropriate to the record type:
//   - A/AAAA: parse both sides as IPs and compare numerically, so equivalent
//     textual forms (uppercase or expanded IPv6) still match.
//   - MX, CNAME: hostnames are case-insensitive (RFC 4343); compare
//     case-folded.
//   - SRV: "priority weight port target"; numbers compared numerically, the
//     target case-folded.
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
	case dnslib.TypeMX, dnslib.TypeCNAME:
		return hostEqual(answer, expected)
	case dnslib.TypeSRV:
		a, okA := parseSRV(answer)
		e, okE := parseSRV(expected)
		return okA && okE && a.priority == e.priority && a.weight == e.weight && a.port == e.port && hostEqual(a.target, e.target)
	default: // TXT and any other text-valued type: case-sensitive.
		return answer == expected
	}
}

// hostEqual compares two host names case-insensitively, ignoring a trailing dot.
func hostEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// srvValue is the parsed form of an SRV answer or expected value.
type srvValue struct {
	priority, weight, port uint16
	target                 string
}

// parseSRV parses the zone-file form "priority weight port target" used for SRV
// answers and expected values. Any run of whitespace separates the fields.
//
// Parameters:
//   - s: the text to parse.
//
// It returns the parsed value and true, or false when s does not have exactly
// four fields or a number is not a valid uint16.
func parseSRV(s string) (srvValue, bool) {
	fields := strings.Fields(s)
	if len(fields) != 4 {
		return srvValue{}, false
	}
	var nums [3]uint16
	for i := range nums {
		n, err := strconv.ParseUint(fields[i], 10, 16)
		if err != nil {
			return srvValue{}, false
		}
		nums[i] = uint16(n)
	}
	return srvValue{priority: nums[0], weight: nums[1], port: nums[2], target: fields[3]}, true
}

// withDefaultPort appends the default DNS port when the server has none.
func withDefaultPort(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, defaultPort)
}
