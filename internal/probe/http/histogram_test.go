package http

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

// histogramStats returns the sample count and sum of the histogram series named
// `name` whose labels contain `want`, plus whether it was found.
func histogramStats(t *testing.T, reg *prometheus.Registry, name string, want map[string]string) (uint64, float64, bool) {
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
			if m.Histogram != nil && labelsContain(m.GetLabel(), want) {
				return m.Histogram.GetSampleCount(), m.Histogram.GetSampleSum(), true
			}
		}
	}
	return 0, 0, false
}

func ttfbRecord(name, typ string, success bool, ttfb time.Duration) store.Record {
	return store.Record{
		Target: name,
		Type:   typ,
		Labels: map[string]string{"environment": "prod"},
		Result: probe.Result{Success: success, Timings: probe.Timings{TTFB: ttfb}},
	}
}

func TestTTFBObserverSkipsNonEligible(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	obs := NewTTFBObserver(reg)

	obs.Observe(ttfbRecord("ok", ProbeType, true, 80*time.Millisecond))    // recorded
	obs.Observe(ttfbRecord("ok", ProbeType, true, 120*time.Millisecond))   // recorded
	obs.Observe(ttfbRecord("dns", "dns", true, 90*time.Millisecond))       // wrong type: skipped
	obs.Observe(ttfbRecord("fail", ProbeType, false, 90*time.Millisecond)) // failure: skipped
	obs.Observe(ttfbRecord("zero", ProbeType, true, 0))                    // no first byte: skipped

	count, sum, ok := histogramStats(t, reg, "sentinel_http_ttfb_seconds", map[string]string{"target": "ok"})
	if !ok {
		t.Fatal("sentinel_http_ttfb_seconds absent for ok")
	}
	if count != 2 {
		t.Errorf("sample count = %d, want 2", count)
	}
	if sum < 0.199 || sum > 0.201 {
		t.Errorf("sample sum = %v, want ~0.20", sum)
	}

	for _, name := range []string{"dns", "fail", "zero"} {
		if _, _, ok := histogramStats(t, reg, "sentinel_http_ttfb_seconds", map[string]string{"target": name}); ok {
			t.Errorf("target %q must not be observed", name)
		}
	}
}
