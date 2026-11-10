package dns

import (
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dnslib "github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

// zoneHandler is a recursive-resolver stand-in that answers from zone-file
// lines, keyed by question name and type. A name present with no line of the
// asked type gets NOERROR/empty; an unknown name gets NXDOMAIN.
func zoneHandler(t *testing.T, lines ...string) dnslib.HandlerFunc {
	t.Helper()
	records := map[string][]dnslib.RR{}
	names := map[string]bool{}
	for _, l := range lines {
		rr, err := dnslib.NewRR(l)
		if err != nil {
			t.Fatalf("bad RR %q: %v", l, err)
		}
		name := strings.ToLower(rr.Header().Name)
		names[name] = true
		key := fmt.Sprintf("%s/%d", name, rr.Header().Rrtype)
		records[key] = append(records[key], rr)
	}
	return func(w dnslib.ResponseWriter, r *dnslib.Msg) {
		q := r.Question[0]
		m := new(dnslib.Msg)
		m.SetReply(r)
		name := strings.ToLower(q.Name)
		if !names[name] {
			m.Rcode = dnslib.RcodeNameError
		}
		m.Answer = records[fmt.Sprintf("%s/%d", name, q.Qtype)]
		_ = w.WriteMsg(m)
	}
}

// nameserver is a fake authoritative server for example.org.
type nameserver struct {
	serial        uint32
	authoritative bool
	rcode         int
	// recursionAsked counts queries that arrived with RD set.
	recursionAsked atomic.Int32
}

func (n *nameserver) handler() dnslib.HandlerFunc {
	return func(w dnslib.ResponseWriter, r *dnslib.Msg) {
		if r.RecursionDesired {
			n.recursionAsked.Add(1)
		}
		m := new(dnslib.Msg)
		m.SetRcode(r, n.rcode)
		m.Authoritative = n.authoritative
		if n.rcode == dnslib.RcodeSuccess {
			soa, _ := dnslib.NewRR(fmt.Sprintf("example.org. 3600 IN SOA ns1.example.net. hostmaster.example.org. %d 7200 900 1209600 300", n.serial))
			m.Answer = []dnslib.RR{soa}
		}
		_ = w.WriteMsg(m)
	}
}

// delegation is the resolver's view of example.org: two nameservers with one
// IPv4 address each, and an IPv6 address for ns1.
var delegation = []string{
	"example.org. 3600 IN NS ns1.example.net.",
	"example.org. 3600 IN NS NS2.example.net.", // case must not matter
	"ns1.example.net. 3600 IN A 192.0.2.1",
	"ns1.example.net. 3600 IN AAAA 2001:db8::1",
	"ns2.example.net. 3600 IN A 192.0.2.2",
}

// authProber builds an authoritative-check prober whose nameserver addresses
// are redirected to local test servers.
func authProber(t *testing.T, resolver string, family Family, servers map[string]string) *Prober {
	t.Helper()
	p, err := New(Options{
		Name: "zone", Servers: []string{resolver}, Query: "example.org",
		Timeout: 2 * time.Second, Authoritative: true, Family: family,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.nsTarget = func(a netip.Addr) string {
		if target, ok := servers[a.String()]; ok {
			return target
		}
		t.Errorf("probe queried unexpected nameserver address %s", a)
		return "127.0.0.1:1"
	}
	return p
}

func TestAuthoritativeHealthy(t *testing.T) {
	t.Parallel()

	ns1 := &nameserver{serial: 2026111001, authoritative: true}
	ns2 := &nameserver{serial: 2026111001, authoritative: true}
	resolver := startTestDNS(t, zoneHandler(t, delegation...))
	p := authProber(t, resolver, "", map[string]string{
		"192.0.2.1": startTestDNS(t, ns1.handler()),
		"192.0.2.2": startTestDNS(t, ns2.handler()),
	})

	res := p.Probe(t.Context())
	if !res.Success {
		t.Fatalf("probe failed: %q", res.FailureReason)
	}
	d := diag(t, res)
	if got := strings.Join(d.Answers, ","); got != "ns1.example.net,ns2.example.net" {
		t.Errorf("nameservers = %q", got)
	}
	if len(d.Nameservers) != 2 || !d.Consistent {
		t.Fatalf("nameservers=%d consistent=%v, want 2/true (IPv4 only by default)", len(d.Nameservers), d.Consistent)
	}
	for _, ns := range d.Nameservers {
		if !ns.Authoritative || !ns.HasSerial || ns.Serial != 2026111001 {
			t.Errorf("nameserver %s = %+v, want authoritative serial 2026111001", ns.Host, ns)
		}
	}
	if n := ns1.recursionAsked.Load() + ns2.recursionAsked.Load(); n != 0 {
		t.Errorf("%d SOA queries asked for recursion; an authoritative server must answer from its own data", n)
	}
}

func TestAuthoritativeFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ns2  *nameserver
		want probe.FailureReason
	}{
		{"serial behind", &nameserver{serial: 2026110901, authoritative: true}, probe.ReasonDNSMismatch},
		{"answers without authority", &nameserver{serial: 2026111001}, probe.ReasonDNSLameDelegation},
		{"refuses the zone", &nameserver{rcode: dnslib.RcodeRefused}, probe.ReasonDNSLameDelegation},
		{"server failure", &nameserver{rcode: dnslib.RcodeServerFailure, authoritative: true}, probe.ReasonDNSError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ns1 := &nameserver{serial: 2026111001, authoritative: true}
			resolver := startTestDNS(t, zoneHandler(t, delegation...))
			p := authProber(t, resolver, FamilyIPv4, map[string]string{
				"192.0.2.1": startTestDNS(t, ns1.handler()),
				"192.0.2.2": startTestDNS(t, tc.ns2.handler()),
			})
			res := p.Probe(t.Context())
			if res.FailureReason != tc.want {
				t.Fatalf("reason = %q, want %q", res.FailureReason, tc.want)
			}
			// The healthy nameserver must still be described.
			if d := diag(t, res); len(d.Nameservers) != 2 || !d.Nameservers[0].HasSerial {
				t.Errorf("nameserver results lost: %+v", d.Nameservers)
			}
		})
	}
}

// TestAuthoritativeVerdictOrder: an unreachable nameserver outranks a lame one,
// and a lame one outranks a serial difference.
func TestAuthoritativeVerdictOrder(t *testing.T) {
	t.Parallel()

	lame := NameserverResult{Reason: probe.ReasonDNSLameDelegation}
	down := NameserverResult{Reason: probe.ReasonTimeout}
	ok := NameserverResult{HasSerial: true}
	if got := authoritativeVerdict([]NameserverResult{lame, down}, false); got != probe.ReasonTimeout {
		t.Errorf("lame+down = %q, want timeout", got)
	}
	if got := authoritativeVerdict([]NameserverResult{ok, lame}, false); got != probe.ReasonDNSLameDelegation {
		t.Errorf("lame+mismatch = %q, want dns_lame_delegation", got)
	}
}

func TestAuthoritativeDiscoveryFailures(t *testing.T) {
	t.Parallel()

	t.Run("zone does not exist", func(t *testing.T) {
		t.Parallel()
		p := authProber(t, startTestDNS(t, zoneHandler(t)), "", nil)
		res := p.Probe(t.Context())
		if res.FailureReason != probe.ReasonDNSError {
			t.Fatalf("reason = %q, want dns_error", res.FailureReason)
		}
		if d := diag(t, res); d.ResponseCodeText != "NXDOMAIN" || d.Nameservers != nil {
			t.Errorf("diagnostics = %+v, want NXDOMAIN without nameserver results", d)
		}
	})

	t.Run("name is not a zone apex", func(t *testing.T) {
		t.Parallel()
		p := authProber(t, startTestDNS(t, zoneHandler(t, "example.org. 60 IN A 192.0.2.80")), "", nil)
		if res := p.Probe(t.Context()); res.FailureReason != probe.ReasonDNSError {
			t.Fatalf("reason = %q, want dns_error", res.FailureReason)
		}
	})

	t.Run("nameserver name does not resolve", func(t *testing.T) {
		t.Parallel()
		ns1 := &nameserver{serial: 1, authoritative: true}
		resolver := startTestDNS(t, zoneHandler(t,
			"example.org. 3600 IN NS ns1.example.net.",
			"example.org. 3600 IN NS ghost.example.net.",
			"ns1.example.net. 3600 IN A 192.0.2.1",
		))
		p := authProber(t, resolver, "", map[string]string{"192.0.2.1": startTestDNS(t, ns1.handler())})
		res := p.Probe(t.Context())
		if res.FailureReason != probe.ReasonDNSError {
			t.Fatalf("reason = %q, want dns_error", res.FailureReason)
		}
		var ghost *NameserverResult
		for i, ns := range diag(t, res).Nameservers {
			if ns.Host == "ghost.example.net" {
				ghost = &diag(t, res).Nameservers[i]
			}
		}
		if ghost == nil || ghost.Address != "" || ghost.ResponseCode != -1 {
			t.Errorf("unresolvable nameserver = %+v, want an entry without address", ghost)
		}
	})

	t.Run("nameserver silent", func(t *testing.T) {
		t.Parallel()
		ns1 := &nameserver{serial: 1, authoritative: true}
		resolver := startTestDNS(t, zoneHandler(t, delegation...))
		p := authProber(t, resolver, "", map[string]string{
			"192.0.2.1": startTestDNS(t, ns1.handler()),
			"192.0.2.2": silentResolver(t),
		})
		p.timeout = 300 * time.Millisecond
		res := p.Probe(t.Context())
		if !res.FailureReason.IsTimeout() || res.TimeoutPhase != probe.PhaseDNS {
			t.Fatalf("reason=%q phase=%q, want a timeout in dns", res.FailureReason, res.TimeoutPhase)
		}
	})
}

func TestAuthoritativeFamilies(t *testing.T) {
	t.Parallel()

	healthy := func() string {
		return startTestDNS(t, (&nameserver{serial: 7, authoritative: true}).handler())
	}
	tests := []struct {
		family Family
		want   []string // queried addresses, by original IP
	}{
		{FamilyIPv4, []string{"192.0.2.1", "192.0.2.2"}},
		{FamilyIPv6, []string{"2001:db8::1"}},
		{FamilyBoth, []string{"192.0.2.1", "2001:db8::1", "192.0.2.2"}},
	}
	for _, tc := range tests {
		t.Run(string(tc.family), func(t *testing.T) {
			t.Parallel()
			servers := map[string]string{}
			back := map[string]string{}
			for _, ip := range tc.want {
				servers[ip] = healthy()
				back[servers[ip]] = ip
			}
			p := authProber(t, startTestDNS(t, zoneHandler(t, delegation...)), tc.family, servers)
			res := p.Probe(t.Context())

			var got []string
			for _, ns := range diag(t, res).Nameservers {
				if ip, ok := back[ns.Address]; ok {
					got = append(got, ip)
				}
			}
			if len(got) != len(tc.want) {
				t.Errorf("queried %v, want %v", got, tc.want)
			}
			if tc.family == FamilyIPv6 {
				// ns2 has no IPv6 address: it cannot be checked in this family,
				// which must show as a failure rather than silently vanish.
				if res.FailureReason != probe.ReasonDNSError {
					t.Errorf("reason = %q, want dns_error for a nameserver without an address in the family", res.FailureReason)
				}
			} else if !res.Success {
				t.Errorf("probe failed: %q", res.FailureReason)
			}
		})
	}
}

func TestNSHostsCapped(t *testing.T) {
	t.Parallel()

	m := new(dnslib.Msg)
	for i := range maxNameservers + 4 {
		rr, _ := dnslib.NewRR(fmt.Sprintf("example.org. 60 IN NS ns%02d.example.net.", i))
		m.Answer = append(m.Answer, rr, rr) // duplicates are folded
	}
	other, _ := dnslib.NewRR("sub.example.org. 60 IN NS ns.elsewhere.net.")
	m.Answer = append(m.Answer, other)

	hosts := nsHosts(m, "example.org.")
	if len(hosts) != maxNameservers {
		t.Errorf("got %d nameservers, want the cap of %d", len(hosts), maxNameservers)
	}
	for _, h := range hosts {
		if h == "ns.elsewhere.net" {
			t.Error("NS record of another owner name was taken")
		}
	}
}

func TestNewRejectsUnknownFamily(t *testing.T) {
	t.Parallel()
	_, err := New(Options{Servers: []string{"1.1.1.1"}, Query: "example.org", Timeout: time.Second, Authoritative: true, Family: "ipv5"})
	if err == nil {
		t.Fatal("expected an error for an unknown family")
	}
}

func TestCollectorNameservers(t *testing.T) {
	t.Parallel()

	rec := store.Record{
		Target: "zone", Type: ProbeType,
		Result: probe.Result{Diagnostics: &Diagnostics{
			Consistent: false,
			Nameservers: []NameserverResult{
				{Host: "ns1.example.net", Address: "192.0.2.1:53", Authoritative: true, Serial: 2026111001, HasSerial: true},
				{Host: "ns2.example.net", Address: "192.0.2.2:53", ResponseCode: -1, Reason: probe.ReasonTimeout},
			},
		}},
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: []store.Record{rec}}))

	ns1 := map[string]string{"target": "zone", "nameserver": "ns1.example.net", "address": "192.0.2.1:53"}
	ns2 := map[string]string{"target": "zone", "nameserver": "ns2.example.net", "address": "192.0.2.2:53"}
	if v, ok := gatherValue(t, reg, "sentinel_dns_nameserver_soa_serial", ns1); !ok || v != 2026111001 {
		t.Errorf("ns1 serial = %v ok=%v", v, ok)
	}
	if _, ok := gatherValue(t, reg, "sentinel_dns_nameserver_soa_serial", ns2); ok {
		t.Error("serial emitted for a nameserver that did not answer")
	}
	if v, ok := gatherValue(t, reg, "sentinel_dns_nameserver_response_code", ns2); !ok || v != -1 {
		t.Errorf("ns2 response code = %v ok=%v, want -1", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_dns_nameserver_authoritative", ns2); !ok || v != 0 {
		t.Errorf("ns2 authoritative = %v ok=%v, want 0", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_dns_answers_consistent", map[string]string{"target": "zone"}); !ok || v != 0 {
		t.Errorf("consistent = %v ok=%v, want 0", v, ok)
	}
	// The resolver-comparison series belong to dns.servers targets only.
	if _, ok := gatherValue(t, reg, "sentinel_dns_resolver_answer_count", map[string]string{"target": "zone"}); ok {
		t.Error("resolver series emitted for an authoritative target")
	}
}
