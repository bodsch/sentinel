package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/scheduler"
	"bodsch.me/sentinel/internal/store"
)

type fakeResults struct{ recs []store.Record }

func (f fakeResults) Snapshot() []store.Record { return f.recs }

type fakeSkips struct{ stats []scheduler.JobStat }

func (f fakeSkips) Stats() []scheduler.JobStat { return f.stats }

// gatherValue finds the value of the first metric named `name` whose labels
// include all of `want`. It returns the value and whether such a series exists.
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

func TestProbeCollector(t *testing.T) {
	t.Parallel()

	results := fakeResults{recs: []store.Record{
		{
			Target: "ok", Type: "http",
			Labels:      map[string]string{"environment": "prod"},
			Result:      probe.Result{Success: true, Duration: 150 * time.Millisecond, Timestamp: time.Unix(1000, 0)},
			LastSuccess: time.Unix(1000, 0),
		},
		{
			Target: "bad", Type: "http",
			Result: probe.Result{Success: false, FailureReason: probe.ReasonTimeout, Duration: 50 * time.Millisecond},
		},
	}}
	skips := fakeSkips{stats: []scheduler.JobStat{
		{Name: "ok", Type: "http", Labels: map[string]string{"environment": "prod"}, Skipped: 3},
	}}

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewProbeCollector(results, skips))

	// success
	if v, ok := gatherValue(t, reg, "sentinel_probe_success", map[string]string{"target": "ok"}); !ok || v != 1 {
		t.Errorf("probe_success{ok} = %v ok=%v, want 1", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_probe_success", map[string]string{"target": "bad"}); !ok || v != 0 {
		t.Errorf("probe_success{bad} = %v ok=%v, want 0", v, ok)
	}

	// duration
	if v, ok := gatherValue(t, reg, "sentinel_probe_duration_seconds", map[string]string{"target": "ok"}); !ok || v != 0.15 {
		t.Errorf("probe_duration{ok} = %v, want 0.15", v)
	}

	// failure_info: present for the failing target with the reason, absent for ok
	if _, ok := gatherValue(t, reg, "sentinel_probe_failure_info", map[string]string{"target": "bad", "reason": "timeout"}); !ok {
		t.Error("expected failure_info{bad,timeout} to be present")
	}
	if _, ok := gatherValue(t, reg, "sentinel_probe_failure_info", map[string]string{"target": "ok"}); ok {
		t.Error("failure_info{ok} must be absent on success (vanishing semantics)")
	}

	// last_success: present for ok, absent for bad (never succeeded)
	if _, ok := gatherValue(t, reg, "sentinel_probe_last_success_timestamp_seconds", map[string]string{"target": "ok"}); !ok {
		t.Error("expected last_success{ok} to be present")
	}
	if _, ok := gatherValue(t, reg, "sentinel_probe_last_success_timestamp_seconds", map[string]string{"target": "bad"}); ok {
		t.Error("last_success{bad} must be absent for a never-successful target")
	}

	// skipped counter
	if v, ok := gatherValue(t, reg, "sentinel_probe_skipped_total", map[string]string{"target": "ok"}); !ok || v != 3 {
		t.Errorf("probe_skipped_total{ok} = %v, want 3", v)
	}

	// label consistency: environment carried through
	if _, ok := gatherValue(t, reg, "sentinel_probe_success", map[string]string{"target": "ok", "environment": "prod"}); !ok {
		t.Error("expected environment label on probe_success{ok}")
	}
}

func TestRegistryHasBuildInfo(t *testing.T) {
	t.Parallel()

	reg := NewRegistry()
	if _, ok := gatherValue(t, reg, "sentinel_build_info", nil); !ok {
		t.Error("expected sentinel_build_info to be registered")
	}
}
