package dns

import (
	"net"
	"testing"
	"time"

	dnslib "github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

// compareOpts builds options querying several resolvers.
func compareOpts(typ string, servers ...string) Options {
	return Options{Name: "cmp", Servers: servers, Query: "example.org", Type: typ, Timeout: 3 * time.Second}
}

// rcodeHandler answers every question with the given RCODE and no records.
func rcodeHandler(rcode int) dnslib.HandlerFunc {
	return func(w dnslib.ResponseWriter, r *dnslib.Msg) {
		m := new(dnslib.Msg)
		m.SetRcode(r, rcode)
		_ = w.WriteMsg(m)
	}
}

// delayedHandler answers like next, after a delay.
func delayedHandler(d time.Duration, next dnslib.HandlerFunc) dnslib.HandlerFunc {
	return func(w dnslib.ResponseWriter, r *dnslib.Msg) {
		time.Sleep(d)
		next(w, r)
	}
}

// silentResolver is a UDP socket that never answers.
func silentResolver(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

func TestCompareConsistent(t *testing.T) {
	t.Parallel()

	// Same set, different order, case and duplicates: not a difference.
	a := startTestDNS(t, answerHandler(t, "example.org. 60 IN MX 10 mx1.example.org.", "example.org. 60 IN MX 20 mx2.example.org."))
	b := startTestDNS(t, answerHandler(t, "example.org. 300 IN MX 20 MX2.Example.org.", "example.org. 300 IN MX 10 mx1.example.org.", "example.org. 300 IN MX 10 mx1.example.org."))

	res := run(t, compareOpts("MX", a, b))
	if !res.Success {
		t.Fatalf("probe failed: %q", res.FailureReason)
	}
	d := diag(t, res)
	if !d.Consistent || len(d.Resolvers) != 2 {
		t.Fatalf("consistent=%v resolvers=%d, want true/2", d.Consistent, len(d.Resolvers))
	}
	if d.Resolvers[0].Server != a || d.Resolvers[1].Server != b {
		t.Errorf("resolver order = %s, %s; want configured order", d.Resolvers[0].Server, d.Resolvers[1].Server)
	}
	// The top level describes the first resolver, as for a single one.
	if d.AnswerCount != 2 {
		t.Errorf("answer count = %d, want the first resolver's 2", d.AnswerCount)
	}
}

func TestCompareMismatch(t *testing.T) {
	t.Parallel()

	a := startTestDNS(t, answerHandler(t, "example.org. 60 IN A 192.0.2.1"))
	b := startTestDNS(t, answerHandler(t, "example.org. 60 IN A 192.0.2.1", "example.org. 60 IN A 192.0.2.2"))

	res := run(t, compareOpts("A", a, b))
	if res.Success || res.FailureReason != probe.ReasonDNSMismatch {
		t.Fatalf("success=%v reason=%q, want dns_mismatch", res.Success, res.FailureReason)
	}
	if d := diag(t, res); d.Consistent {
		t.Error("consistent = true for differing answer sets")
	}
}

// TestCompareEmptyVersusAnswer: one resolver returning NOERROR with no records
// (a stale negative cache) must count as a difference, not as "no opinion".
func TestCompareEmptyVersusAnswer(t *testing.T) {
	t.Parallel()

	a := startTestDNS(t, answerHandler(t, "example.org. 60 IN A 192.0.2.1"))
	b := startTestDNS(t, answerHandler(t))

	res := run(t, compareOpts("A", a, b))
	if res.FailureReason != probe.ReasonDNSMismatch {
		t.Fatalf("reason = %q, want dns_mismatch", res.FailureReason)
	}
}

func TestCompareOneResolverFails(t *testing.T) {
	t.Parallel()

	good := answerHandler(t, "example.org. 60 IN A 192.0.2.1")

	t.Run("nxdomain on the second", func(t *testing.T) {
		t.Parallel()
		res := run(t, compareOpts("A", startTestDNS(t, good), startTestDNS(t, rcodeHandler(dnslib.RcodeNameError))))
		if res.FailureReason != probe.ReasonDNSError {
			t.Fatalf("reason = %q, want dns_error", res.FailureReason)
		}
		d := diag(t, res)
		if r := d.Resolvers[1]; r.Reason != probe.ReasonDNSError || r.ResponseCodeText != "NXDOMAIN" {
			t.Errorf("second resolver = %+v, want dns_error/NXDOMAIN", r)
		}
		if d.Resolvers[0].Reason != probe.ReasonNone {
			t.Errorf("first resolver reason = %q, want none", d.Resolvers[0].Reason)
		}
	})

	t.Run("first resolver silent", func(t *testing.T) {
		t.Parallel()
		o := compareOpts("A", silentResolver(t), startTestDNS(t, good))
		o.Timeout = 300 * time.Millisecond
		res := run(t, o)
		if !res.FailureReason.IsTimeout() {
			t.Fatalf("reason = %q, want a timeout", res.FailureReason)
		}
		if res.TimeoutPhase != probe.PhaseDNS {
			t.Errorf("phase = %q, want dns", res.TimeoutPhase)
		}
		// Unlike a single resolver, the others are still worth describing.
		d := diag(t, res)
		if len(d.Resolvers[1].Answers) != 1 {
			t.Errorf("answering resolver lost its answers: %+v", d.Resolvers[1])
		}
		if !d.Consistent {
			t.Error("a silent resolver has no answer set and must not count as a mismatch")
		}
	})
}

// TestCompareExpectedPerResolver: the expected set applies to every resolver,
// so a resolver serving a stale record fails the check even if another is right.
func TestCompareExpectedPerResolver(t *testing.T) {
	t.Parallel()

	a := startTestDNS(t, answerHandler(t, "example.org. 60 IN A 192.0.2.1"))
	b := startTestDNS(t, answerHandler(t, "example.org. 60 IN A 198.51.100.7"))

	o := compareOpts("A", a, b)
	o.Expected = []string{"192.0.2.1"}
	if res := run(t, o); res.FailureReason != probe.ReasonValidationFailed {
		t.Fatalf("reason = %q, want validation_failed", res.FailureReason)
	}
}

// TestCompareRunsInParallel: the probe takes as long as the slowest resolver,
// not the sum of all of them.
func TestCompareRunsInParallel(t *testing.T) {
	t.Parallel()

	slow := delayedHandler(250*time.Millisecond, answerHandler(t, "example.org. 60 IN A 192.0.2.1"))
	o := compareOpts("A", startTestDNS(t, slow), startTestDNS(t, slow), startTestDNS(t, slow))

	res := run(t, o)
	if !res.Success {
		t.Fatalf("probe failed: %q", res.FailureReason)
	}
	if res.Duration > 600*time.Millisecond {
		t.Errorf("duration = %v for three 250ms resolvers, want them queried in parallel", res.Duration)
	}
	for _, r := range diag(t, res).Resolvers {
		if r.Duration < 200*time.Millisecond {
			t.Errorf("resolver %s duration = %v, want its own measured time", r.Server, r.Duration)
		}
	}
}

func TestNewRequiresServers(t *testing.T) {
	t.Parallel()

	for _, servers := range [][]string{nil, {"1.1.1.1", "  "}} {
		if _, err := New(Options{Servers: servers, Query: "example.org", Type: "A", Timeout: time.Second}); err == nil {
			t.Errorf("New with servers %q succeeded, want an error", servers)
		}
	}
}

func TestCollectorPerResolver(t *testing.T) {
	t.Parallel()

	a := startTestDNS(t, answerHandler(t, "example.org. 60 IN A 192.0.2.1"))
	silent := silentResolver(t)
	o := compareOpts("A", a, silent)
	o.Timeout = 300 * time.Millisecond
	multi := run(t, o)
	single := run(t, opts(a, "example.org", "A"))

	recs := []store.Record{
		{Target: "multi", Type: ProbeType, Result: multi},
		{Target: "single", Type: ProbeType, Result: single},
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: recs}))
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	values := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			var target, resolver string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "target":
					target = lp.GetValue()
				case "resolver":
					resolver = lp.GetValue()
				}
			}
			key := mf.GetName() + "|" + target
			if resolver != "" {
				key += "|" + resolver
			}
			values[key] = m.GetGauge().GetValue()
		}
	}

	if v, ok := values["sentinel_dns_resolver_response_code|multi|"+silent]; !ok || v != -1 {
		t.Errorf("silent resolver response code = %v ok=%v, want -1", v, ok)
	}
	if v, ok := values["sentinel_dns_resolver_answer_count|multi|"+a]; !ok || v != 1 {
		t.Errorf("answering resolver answer count = %v ok=%v, want 1", v, ok)
	}
	if v, ok := values["sentinel_dns_answers_consistent|multi"]; !ok || v != 1 {
		t.Errorf("answers consistent = %v ok=%v, want 1", v, ok)
	}
	// A single-resolver target keeps exactly its previous series.
	for key := range values {
		if key == "sentinel_dns_answers_consistent|single" || key == "sentinel_dns_resolver_query_duration_seconds|single|"+a {
			t.Errorf("per-resolver series %q emitted for a single-resolver target", key)
		}
	}
}
