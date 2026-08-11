package http

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
	"bodsch.me/sentinel/internal/tlsdiag"
)

type fakeResults struct{ recs []store.Record }

func (f fakeResults) Snapshot() []store.Record { return f.recs }

func gatherValue(t *testing.T, reg *prometheus.Registry, name string, want map[string]string) (float64, bool) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if labelsContain(m.GetLabel(), want) {
				switch {
				case m.Gauge != nil:
					return m.Gauge.GetValue(), true
				case m.Counter != nil:
					return m.Counter.GetValue(), true
				}
			}
		}
	}
	return 0, false
}

func labelsContain(have []*dto.LabelPair, want map[string]string) bool {
	index := make(map[string]string, len(have))
	for _, lp := range have {
		index[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if index[k] != v {
			return false
		}
	}
	return true
}

func TestHTTPCollector(t *testing.T) {
	t.Parallel()

	rec := store.Record{
		Target: "site", Type: ProbeType,
		Labels: map[string]string{"service": "web"},
		Result: probe.Result{
			Success: true,
			Timings: probe.Timings{
				DNS:      5 * time.Millisecond,
				Connect:  12 * time.Millisecond,
				TLS:      35 * time.Millisecond,
				TTFB:     80 * time.Millisecond,
				Download: 5 * time.Millisecond,
			},
			Diagnostics: &Diagnostics{
				FinalURL:   "https://site/",
				StatusCode: 200,
				Redirects:  []RedirectStep{{URL: "https://site/old", StatusCode: 301}},
				TLS:        &tlsdiag.Info{ExpiresAt: time.Unix(2000, 0), RemainingDays: 42, HostnameValid: true, Valid: true},
			},
		},
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: []store.Record{rec}}))

	want := map[string]string{"target": "site"}
	checks := []struct {
		name string
		val  float64
	}{
		{"sentinel_http_status_code", 200},
		{"sentinel_http_dns_duration_seconds", 0.005},
		{"sentinel_http_tls_handshake_duration_seconds", 0.035},
		// sentinel_http_ttfb_seconds is now a histogram fed by TTFBObserver
		// (see histogram_test.go), no longer a collector gauge.
		{"sentinel_http_redirects", 1},
		{"sentinel_http_ssl", 1},
	}
	for _, c := range checks {
		if v, ok := gatherValue(t, reg, c.name, want); !ok || v != c.val {
			t.Errorf("%s = %v ok=%v, want %v", c.name, v, ok, c.val)
		}
	}

	// The certificate series moved to the protocol-independent tlsdiag
	// collector; the HTTP collector must not emit them a second time (a
	// duplicate registration would make the whole scrape fail).
	if _, ok := gatherValue(t, reg, "sentinel_tls_certificate_valid", want); ok {
		t.Error("HTTP collector must not emit sentinel_tls_* series")
	}
}

func TestHTTPCollectorSkipsNonHTTPAndPlainTLS(t *testing.T) {
	t.Parallel()

	recs := []store.Record{
		// Non-http record: ignored.
		{Target: "dns1", Type: "dns", Result: probe.Result{Diagnostics: nil}},
		// Plain HTTP (no TLS): http_ssl must report 0.
		{
			Target: "plain", Type: ProbeType,
			Result: probe.Result{Success: true, Diagnostics: &Diagnostics{StatusCode: 200}},
		},
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: recs}))

	if _, ok := gatherValue(t, reg, "sentinel_http_status_code", map[string]string{"target": "dns1"}); ok {
		t.Error("non-http record should not produce http metrics")
	}
	if v, ok := gatherValue(t, reg, "sentinel_http_status_code", map[string]string{"target": "plain"}); !ok || v != 200 {
		t.Errorf("plain http status = %v ok=%v, want 200", v, ok)
	}
	// Unlike the certificate series, http_ssl is reported for plain HTTP too:
	// a target dropping from https to http must show as 1 -> 0, not as a gap.
	if v, ok := gatherValue(t, reg, "sentinel_http_ssl", map[string]string{"target": "plain"}); !ok || v != 0 {
		t.Errorf("plain http ssl = %v ok=%v, want 0", v, ok)
	}
}
