package tls

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

// gatherValue returns the value of the named series whose labels include want.
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
				return m.GetGauge().GetValue(), true
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

func TestCollector(t *testing.T) {
	t.Parallel()

	rec := store.Record{
		Target: "ldaps", Type: ProbeType,
		Labels: map[string]string{"service": "directory"},
		Result: probe.Result{
			Success: true,
			Timings: probe.Timings{
				DNS:     3 * time.Millisecond,
				Connect: 12 * time.Millisecond,
				TLS:     40 * time.Millisecond,
			},
			Diagnostics: &Diagnostics{
				Endpoint: "192.0.2.1:636",
				TLS:      &tlsdiag.Info{Valid: true},
			},
		},
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: []store.Record{rec}}))
	want := map[string]string{"target": "ldaps", "service": "directory"}

	checks := []struct {
		name string
		want float64
	}{
		{"sentinel_tls_dns_duration_seconds", 0.003},
		{"sentinel_tls_connect_duration_seconds", 0.012},
		{"sentinel_tls_handshake_duration_seconds", 0.040},
	}
	for _, c := range checks {
		if v, ok := gatherValue(t, reg, c.name, want); !ok || v != c.want {
			t.Errorf("%s = %v ok=%v, want %v", c.name, v, ok, c.want)
		}
	}

	// The certificate series come from the shared tlsdiag collector; emitting
	// them here as well would make the whole scrape fail on duplicate series.
	if _, ok := gatherValue(t, reg, "sentinel_tls_certificate_valid", want); ok {
		t.Error("TLS probe collector must not emit sentinel_tls_certificate_* series")
	}
}

// TestCollectorSkipsOtherProbeTypes asserts the timing series stay specific to
// this probe: an HTTPS target measures its handshake through the HTTP collector
// and must not appear here as well.
func TestCollectorSkipsOtherProbeTypes(t *testing.T) {
	t.Parallel()

	recs := []store.Record{
		{
			Target: "web", Type: "http",
			Result: probe.Result{Timings: probe.Timings{TLS: time.Second}},
		},
		{Target: "dns1", Type: "dns", Result: probe.Result{}},
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: recs}))

	for _, target := range []string{"web", "dns1"} {
		for _, name := range []string{
			"sentinel_tls_dns_duration_seconds",
			"sentinel_tls_connect_duration_seconds",
			"sentinel_tls_handshake_duration_seconds",
		} {
			if _, ok := gatherValue(t, reg, name, map[string]string{"target": target}); ok {
				t.Errorf("%s emitted for probe type of target %q", name, target)
			}
		}
	}
}

// TestDiagnosticsFeedSharedCollector proves the wiring that makes the whole
// design work: the TLS probe's diagnostics are picked up by the shared
// certificate collector without that collector knowing this package exists.
func TestDiagnosticsFeedSharedCollector(t *testing.T) {
	t.Parallel()

	rec := store.Record{
		Target: "ldaps", Type: ProbeType,
		Result: probe.Result{
			Success: true,
			Diagnostics: &Diagnostics{
				TLS: &tlsdiag.Info{
					Valid:         true,
					RemainingDays: 42,
					ChainLength:   2,
					ChainVerified: true,
					VersionName:   "TLS 1.3",
					ALPN:          "h2",
				},
			},
		},
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(tlsdiag.NewCollector(fakeResults{recs: []store.Record{rec}}))
	target := map[string]string{"target": "ldaps"}

	if v, ok := gatherValue(t, reg, "sentinel_tls_certificate_remaining_days", target); !ok || v != 42 {
		t.Errorf("remaining days = %v ok=%v, want 42", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_tls_chain_length", target); !ok || v != 2 {
		t.Errorf("chain length = %v ok=%v, want 2", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_tls_alpn_info", map[string]string{"target": "ldaps", "protocol": "h2"}); !ok || v != 1 {
		t.Errorf("alpn info = %v ok=%v, want 1", v, ok)
	}
}
