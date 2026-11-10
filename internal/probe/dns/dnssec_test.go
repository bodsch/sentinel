package dns

import (
	"sync/atomic"
	"testing"
	"time"

	dnslib "github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

// validatingResolver is a fake resolver that answers with a fixed A record set,
// optional RRSIGs and a configurable AD flag, and records what the query asked
// for.
type validatingResolver struct {
	ad      bool
	address string
	// sigs are RRSIG lines added to the answer section.
	sigs []string
	// sawDO and sawAD count queries carrying the DO bit and the AD flag.
	sawDO, sawAD atomic.Int32
}

func (v *validatingResolver) handler(t *testing.T) dnslib.HandlerFunc {
	t.Helper()
	return func(w dnslib.ResponseWriter, r *dnslib.Msg) {
		if opt := r.IsEdns0(); opt != nil && opt.Do() {
			v.sawDO.Add(1)
		}
		if r.AuthenticatedData {
			v.sawAD.Add(1)
		}
		m := new(dnslib.Msg)
		m.SetReply(r)
		m.AuthenticatedData = v.ad
		address := v.address
		if address == "" {
			address = "192.0.2.1"
		}
		a, _ := dnslib.NewRR("example.org. 60 IN A " + address)
		m.Answer = append(m.Answer, a)
		for _, line := range v.sigs {
			rr, err := dnslib.NewRR(line)
			if err != nil {
				t.Errorf("bad RRSIG %q: %v", line, err)
				continue
			}
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	}
}

// rrsig builds an RRSIG line covering typ that expires at exp.
func rrsig(typ string, exp time.Time) string {
	return "example.org. 60 IN RRSIG " + typ + " 13 2 60 " +
		exp.UTC().Format("20060102150405") + " " + exp.Add(-14*24*time.Hour).UTC().Format("20060102150405") +
		" 12345 example.org. dGVzdA=="
}

func dnssecOpts(servers ...string) Options {
	o := compareOpts("A", servers...)
	o.DNSSEC = true
	return o
}

func TestDNSSECValidated(t *testing.T) {
	t.Parallel()

	exp := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	v := &validatingResolver{ad: true, sigs: []string{
		rrsig("A", exp),
		// A signature over another type expires earlier, but says nothing
		// about the A record asked for.
		rrsig("CNAME", exp.Add(-7*24*time.Hour)),
	}}
	res := run(t, dnssecOpts(startTestDNS(t, v.handler(t))))
	if !res.Success {
		t.Fatalf("probe failed: %q", res.FailureReason)
	}
	d := diag(t, res)
	if d.DNSSEC == nil || !d.DNSSEC.Validated {
		t.Fatalf("dnssec = %+v, want validated", d.DNSSEC)
	}
	if !d.DNSSEC.SignatureExpiry.Equal(exp) {
		t.Errorf("signature expiry = %v, want %v (the A record's RRSIG)", d.DNSSEC.SignatureExpiry, exp)
	}
	if v.sawDO.Load() == 0 || v.sawAD.Load() == 0 {
		t.Errorf("query carried DO=%d AD=%d, want both set", v.sawDO.Load(), v.sawAD.Load())
	}
}

func TestDNSSECUnvalidated(t *testing.T) {
	t.Parallel()

	v := &validatingResolver{ad: false}
	res := run(t, dnssecOpts(startTestDNS(t, v.handler(t))))
	if res.FailureReason != probe.ReasonDNSSECUnvalidated {
		t.Fatalf("reason = %q, want dnssec_unvalidated", res.FailureReason)
	}
	if d := diag(t, res); d.DNSSEC == nil || d.DNSSEC.Validated {
		t.Errorf("dnssec = %+v, want present and not validated", d.DNSSEC)
	}
}

// TestDNSSECBogusIsServfail: a validating resolver answers a bogus signature
// with SERVFAIL, which must stay dns_error rather than be reported as merely
// unvalidated.
func TestDNSSECBogusIsServfail(t *testing.T) {
	t.Parallel()

	res := run(t, dnssecOpts(startTestDNS(t, rcodeHandler(dnslib.RcodeServerFailure))))
	if res.FailureReason != probe.ReasonDNSError {
		t.Fatalf("reason = %q, want dns_error", res.FailureReason)
	}
}

func TestDNSSECOff(t *testing.T) {
	t.Parallel()

	v := &validatingResolver{ad: false}
	res := run(t, compareOpts("A", startTestDNS(t, v.handler(t))))
	if !res.Success {
		t.Fatalf("probe failed without dnssec: %q", res.FailureReason)
	}
	if d := diag(t, res); d.DNSSEC != nil {
		t.Errorf("dnssec diagnostics = %+v without dnssec configured", d.DNSSEC)
	}
	if v.sawDO.Load() != 0 {
		t.Error("DO bit set although dnssec is off")
	}
}

func TestDNSSECWithSeveralResolvers(t *testing.T) {
	t.Parallel()

	early := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	late := early.Add(5 * 24 * time.Hour)

	t.Run("one resolver does not validate", func(t *testing.T) {
		t.Parallel()
		good := &validatingResolver{ad: true, sigs: []string{rrsig("A", late)}}
		plain := &validatingResolver{ad: false}
		res := run(t, dnssecOpts(startTestDNS(t, good.handler(t)), startTestDNS(t, plain.handler(t))))
		if res.FailureReason != probe.ReasonDNSSECUnvalidated {
			t.Fatalf("reason = %q, want dnssec_unvalidated", res.FailureReason)
		}
	})

	t.Run("earliest expiry across resolvers", func(t *testing.T) {
		t.Parallel()
		a := &validatingResolver{ad: true, sigs: []string{rrsig("A", late)}}
		b := &validatingResolver{ad: true, sigs: []string{rrsig("A", early)}}
		res := run(t, dnssecOpts(startTestDNS(t, a.handler(t)), startTestDNS(t, b.handler(t))))
		if !res.Success {
			t.Fatalf("probe failed: %q", res.FailureReason)
		}
		if got := diag(t, res).DNSSEC.SignatureExpiry; !got.Equal(early) {
			t.Errorf("signature expiry = %v, want the earliest %v", got, early)
		}
	})

	t.Run("unvalidated outranks a mismatch", func(t *testing.T) {
		t.Parallel()
		a := &validatingResolver{ad: true}
		b := &validatingResolver{ad: false, address: "198.51.100.9"}
		res := run(t, dnssecOpts(startTestDNS(t, a.handler(t)), startTestDNS(t, b.handler(t))))
		if res.FailureReason != probe.ReasonDNSSECUnvalidated {
			t.Fatalf("reason = %q, want dnssec_unvalidated before dns_mismatch", res.FailureReason)
		}
	})
}

func TestCollectorDNSSEC(t *testing.T) {
	t.Parallel()

	exp := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	recs := []store.Record{
		{Target: "signed", Type: ProbeType, Result: probe.Result{Diagnostics: &Diagnostics{
			DNSSEC: &DNSSECInfo{Validated: true, SignatureExpiry: exp},
		}}},
		{Target: "unsigned", Type: ProbeType, Result: probe.Result{Diagnostics: &Diagnostics{
			DNSSEC: &DNSSECInfo{},
		}}},
		{Target: "plain", Type: ProbeType, Result: probe.Result{Diagnostics: &Diagnostics{}}},
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: recs}))

	if v, ok := gatherValue(t, reg, "sentinel_dns_dnssec_validated", map[string]string{"target": "signed"}); !ok || v != 1 {
		t.Errorf("signed validated = %v ok=%v, want 1", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_dns_rrsig_expiry_timestamp_seconds", map[string]string{"target": "signed"}); !ok || v != float64(exp.Unix()) {
		t.Errorf("signed expiry = %v ok=%v, want %d", v, ok, exp.Unix())
	}
	if v, ok := gatherValue(t, reg, "sentinel_dns_dnssec_validated", map[string]string{"target": "unsigned"}); !ok || v != 0 {
		t.Errorf("unsigned validated = %v ok=%v, want 0", v, ok)
	}
	if _, ok := gatherValue(t, reg, "sentinel_dns_rrsig_expiry_timestamp_seconds", map[string]string{"target": "unsigned"}); ok {
		t.Error("expiry emitted without a signature")
	}
	if _, ok := gatherValue(t, reg, "sentinel_dns_dnssec_validated", map[string]string{"target": "plain"}); ok {
		t.Error("dnssec series emitted for a target without dnssec")
	}
}
