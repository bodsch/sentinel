package tcp

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
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
			if labelsContain(m.GetLabel(), want) && m.Gauge != nil {
				return m.Gauge.GetValue(), true
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

func TestTCPCollector(t *testing.T) {
	t.Parallel()

	recs := []store.Record{
		{
			Target: "ssh",
			Type:   ProbeType,
			Labels: map[string]string{"environment": "prod"},
			Result: probe.Result{Success: true, Timings: probe.Timings{Connect: 12 * time.Millisecond}},
		},
		// Non-TCP record: must be ignored.
		{
			Target: "web",
			Type:   "http",
			Result: probe.Result{Success: true, Timings: probe.Timings{Connect: 5 * time.Millisecond}},
		},
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: recs}))

	const name = "sentinel_tcp_connect_duration_seconds"
	if v, ok := gatherValue(t, reg, name, map[string]string{"target": "ssh"}); !ok || v != 0.012 {
		t.Errorf("%s{ssh} = %v ok=%v, want 0.012", name, v, ok)
	}
	if _, ok := gatherValue(t, reg, name, map[string]string{"target": "web"}); ok {
		t.Error("non-TCP record must not produce a tcp_connect_duration series")
	}
}
