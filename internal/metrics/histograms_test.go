package metrics

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

func durationRecord(name string, success bool, d time.Duration) store.Record {
	return store.Record{
		Target: name,
		Type:   "http",
		Labels: map[string]string{"environment": "prod"},
		Result: probe.Result{Success: success, Duration: d},
	}
}

func TestProbeDurationObserverRecordsSuccessOnly(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	obs := NewProbeDurationObserver(reg)

	obs.Observe(durationRecord("ok", true, 150*time.Millisecond))
	obs.Observe(durationRecord("ok", true, 250*time.Millisecond))
	obs.Observe(durationRecord("bad", false, 10*time.Second)) // failure: skipped

	count, sum, ok := histogramStats(t, reg, "sentinel_probe_duration_seconds", map[string]string{"target": "ok"})
	if !ok {
		t.Fatal("sentinel_probe_duration_seconds absent for ok")
	}
	if count != 2 {
		t.Errorf("sample count = %d, want 2", count)
	}
	if sum < 0.399 || sum > 0.401 {
		t.Errorf("sample sum = %v, want ~0.40", sum)
	}

	if _, _, ok := histogramStats(t, reg, "sentinel_probe_duration_seconds", map[string]string{"target": "bad"}); ok {
		t.Error("failed probe must not be observed into the latency histogram")
	}
}
