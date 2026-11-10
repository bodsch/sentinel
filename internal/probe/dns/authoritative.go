package dns

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	dnslib "github.com/miekg/dns"

	"bodsch.me/sentinel/internal/probe"
)

// Family selects which addresses of a zone's nameservers the authoritative
// check queries.
type Family string

// Supported address families.
const (
	// FamilyIPv4 queries the IPv4 addresses only (the default): a monitoring
	// host without an IPv6 route would otherwise fail permanently.
	FamilyIPv4 Family = "ipv4"
	// FamilyIPv6 queries the IPv6 addresses only.
	FamilyIPv6 Family = "ipv6"
	// FamilyBoth queries every address.
	FamilyBoth Family = "both"
)

const (
	// maxNameservers bounds the NS set taken from the delegation. Real zones
	// have two to eight; the cap only protects against a hostile answer.
	maxNameservers = 16
	// maxAddressesPerNameserver bounds the addresses queried per nameserver
	// and family.
	maxAddressesPerNameserver = 4
)

// NameserverResult is the outcome of the SOA query against one address of one
// of the zone's nameservers.
type NameserverResult struct {
	// Host is the nameserver's name from the NS record, without trailing dot.
	Host string
	// Address is the address queried, as "ip:port"; empty when the name could
	// not be resolved.
	Address string
	// Duration is the time the SOA query took.
	Duration time.Duration
	// Reason is ReasonNone when the address answered authoritatively with the
	// zone's SOA, otherwise why it did not.
	Reason probe.FailureReason
	// ResponseCode is the RCODE; -1 when there was no response.
	ResponseCode int
	// Authoritative reports the AA flag of the response.
	Authoritative bool
	// Serial is the SOA serial; valid only when HasSerial is true.
	Serial    uint32
	HasSerial bool
}

// probeAuthoritative checks a zone's delegation: it looks up the NS set through
// the configured resolver, resolves every nameserver, and asks each address
// directly — without recursion — for the zone's SOA.
//
// The verdict is the first failure in this order: the NS lookup itself, a
// nameserver that could not be resolved, did not answer or answered with an
// error code, a nameserver that answered without authority (lame delegation),
// SOA serials that differ between the nameservers (dns_mismatch).
//
// Parameters:
//   - ctx: carries the probe deadline, shared by all stages.
//
// It returns the result; it never fails as an execution.
func (p *Prober) probeAuthoritative(ctx context.Context) probe.Result {
	start := time.Now()
	resolver := p.servers[0]

	nsLookup := p.exchangeType(ctx, resolver, p.query, dnslib.TypeNS, true)
	res := probe.Result{}
	finish := func() probe.Result {
		end := time.Now()
		res.Duration = end.Sub(start)
		res.Timestamp = end
		res.Timings.DNS = res.Duration
		res.Success = res.FailureReason == probe.ReasonNone
		if res.FailureReason.IsTimeout() {
			res.TimeoutPhase = probe.PhaseDNS
		}
		return res
	}

	if nsLookup.err != nil {
		res.FailureReason = nsLookup.Reason
		return finish()
	}
	hosts := nsHosts(nsLookup.msg, p.query)
	diag := &Diagnostics{
		ResponseCode:     nsLookup.ResponseCode,
		ResponseCodeText: nsLookup.ResponseCodeText,
		Answers:          hosts,
		AnswerCount:      len(hosts),
		Consistent:       true,
	}
	res.Diagnostics = diag
	if nsLookup.Reason != probe.ReasonNone {
		res.FailureReason = nsLookup.Reason
		return finish()
	}
	if len(hosts) == 0 {
		// NOERROR without NS records: the name exists but is no zone apex.
		res.FailureReason = probe.ReasonDNSError
		return finish()
	}

	diag.Nameservers = p.queryNameservers(ctx, resolver, hosts)
	diag.Consistent = sameSerial(diag.Nameservers)
	res.FailureReason = authoritativeVerdict(diag.Nameservers, diag.Consistent)
	return finish()
}

// queryNameservers resolves every nameserver and queries each address for the
// zone's SOA, all concurrently.
func (p *Prober) queryNameservers(ctx context.Context, resolver string, hosts []string) []NameserverResult {
	type slot struct {
		host string
		addr netip.Addr
	}

	// Resolve the hosts in parallel; each yields one or more addresses.
	addrs := make([][]netip.Addr, len(hosts))
	reasons := make([]probe.FailureReason, len(hosts))
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Go(func() { addrs[i], reasons[i] = p.resolveHost(ctx, resolver, host) })
	}
	wg.Wait()

	var slots []slot
	var out []NameserverResult
	for i, host := range hosts {
		if len(addrs[i]) == 0 {
			reason := reasons[i]
			if reason == probe.ReasonNone {
				reason = probe.ReasonDNSError // resolved, but not in the selected family
			}
			out = append(out, NameserverResult{Host: host, Reason: reason, ResponseCode: -1})
			continue
		}
		for _, a := range addrs[i] {
			slots = append(slots, slot{host: host, addr: a})
		}
	}

	results := make([]NameserverResult, len(slots))
	for i, s := range slots {
		wg.Go(func() { results[i] = p.querySOA(ctx, s.host, s.addr) })
	}
	wg.Wait()

	out = append(out, results...)
	slices.SortStableFunc(out, func(a, b NameserverResult) int {
		if c := strings.Compare(a.Host, b.Host); c != 0 {
			return c
		}
		return strings.Compare(a.Address, b.Address)
	})
	return out
}

// resolveHost looks up the addresses of one nameserver in the selected family
// through the configured resolver.
//
// It returns up to maxAddressesPerNameserver addresses per family, and the
// failure reason when no lookup produced a usable response.
func (p *Prober) resolveHost(ctx context.Context, resolver, host string) ([]netip.Addr, probe.FailureReason) {
	var types []uint16
	switch p.family {
	case FamilyIPv6:
		types = []uint16{dnslib.TypeAAAA}
	case FamilyBoth:
		types = []uint16{dnslib.TypeA, dnslib.TypeAAAA}
	default:
		types = []uint16{dnslib.TypeA}
	}

	var out []netip.Addr
	reason := probe.ReasonNone
	for _, t := range types {
		r := p.exchangeType(ctx, resolver, dnslib.Fqdn(host), t, true)
		if r.Reason != probe.ReasonNone {
			reason = r.Reason
			continue
		}
		n := 0
		for _, rr := range r.msg.Answer {
			if n == maxAddressesPerNameserver {
				break
			}
			var ip net.IP
			switch v := rr.(type) {
			case *dnslib.A:
				ip = v.A
			case *dnslib.AAAA:
				ip = v.AAAA
			default:
				continue
			}
			if a, ok := netip.AddrFromSlice(ip); ok {
				out = append(out, a.Unmap())
				n++
			}
		}
	}
	if len(out) > 0 {
		return out, probe.ReasonNone
	}
	return nil, reason
}

// querySOA asks one nameserver address for the zone's SOA without recursion.
func (p *Prober) querySOA(ctx context.Context, host string, addr netip.Addr) NameserverResult {
	target := p.nsTarget(addr)
	r := p.exchangeType(ctx, target, p.query, dnslib.TypeSOA, false)

	out := NameserverResult{
		Host:         host,
		Address:      target,
		Duration:     r.Duration,
		Reason:       r.Reason,
		ResponseCode: -1,
	}
	if r.err != nil {
		return out
	}
	out.ResponseCode = r.ResponseCode
	out.Authoritative = r.msg.Authoritative
	for _, rr := range r.msg.Answer {
		if soa, ok := rr.(*dnslib.SOA); ok && hostEqual(soa.Hdr.Name, p.query) {
			out.Serial, out.HasSerial = soa.Serial, true
			break
		}
	}
	switch {
	case r.ResponseCode == dnslib.RcodeRefused:
		// Refusing to answer for a zone it is delegated is the classic lame
		// delegation, not a server fault.
		out.Reason = probe.ReasonDNSLameDelegation
	case out.Reason == probe.ReasonNone && (!out.Authoritative || !out.HasSerial):
		// Answering for the zone without authority, or without its SOA, is a
		// lame delegation too: the parent points at a server that does not
		// serve it.
		out.Reason = probe.ReasonDNSLameDelegation
	}
	return out
}

// defaultNSTarget is the address a nameserver is queried at.
func defaultNSTarget(addr netip.Addr) string {
	return net.JoinHostPort(addr.String(), defaultPort)
}

// authoritativeVerdict classifies the nameserver results; see
// probeAuthoritative for the order.
func authoritativeVerdict(results []NameserverResult, consistent bool) probe.FailureReason {
	for _, r := range results {
		if r.Reason != probe.ReasonNone && r.Reason != probe.ReasonDNSLameDelegation {
			return r.Reason
		}
	}
	for _, r := range results {
		if r.Reason == probe.ReasonDNSLameDelegation {
			return r.Reason
		}
	}
	if !consistent {
		return probe.ReasonDNSMismatch
	}
	return probe.ReasonNone
}

// sameSerial reports whether every nameserver that returned a serial returned
// the same one.
func sameSerial(results []NameserverResult) bool {
	var want uint32
	seen := false
	for _, r := range results {
		if !r.HasSerial {
			continue
		}
		if !seen {
			want, seen = r.Serial, true
			continue
		}
		if r.Serial != want {
			return false
		}
	}
	return true
}

// nsHosts extracts the zone's nameserver names from an NS response, lowercased,
// de-duplicated, sorted and capped at maxNameservers.
func nsHosts(msg *dnslib.Msg, zone string) []string {
	var out []string
	for _, rr := range msg.Answer {
		if ns, ok := rr.(*dnslib.NS); ok && hostEqual(ns.Hdr.Name, zone) {
			out = append(out, strings.ToLower(strings.TrimSuffix(ns.Ns, ".")))
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > maxNameservers {
		out = out[:maxNameservers]
	}
	return out
}
