package dns

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

func TestDNSCollector(t *testing.T) {
	t.Parallel()

	recs := []store.Record{
		{
			Target: "dns-ok", Type: ProbeType,
			Labels: map[string]string{"environment": "prod"},
			Result: probe.Result{
				Success:     true,
				Timings:     probe.Timings{DNS: 4 * time.Millisecond},
				Diagnostics: &Diagnostics{ResponseCode: 0, ResponseCodeText: "NOERROR", AnswerCount: 2, Answers: []string{"1.2.3.4", "5.6.7.8"}},
			},
		},
		// A non-DNS record must be ignored by this collector.
		{Target: "web", Type: "http", Result: probe.Result{Success: true}},
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: recs}))

	if v, ok := gatherValue(t, reg, "sentinel_dns_answer_count", map[string]string{"target": "dns-ok"}); !ok || v != 2 {
		t.Errorf("answer_count = %v ok=%v, want 2", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_dns_response_code", map[string]string{"target": "dns-ok"}); !ok || v != 0 {
		t.Errorf("response_code = %v ok=%v, want 0", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_dns_query_duration_seconds", map[string]string{"target": "dns-ok"}); !ok || v != 0.004 {
		t.Errorf("query_duration = %v ok=%v, want 0.004", v, ok)
	}
	if _, ok := gatherValue(t, reg, "sentinel_dns_answer_count", map[string]string{"target": "web"}); ok {
		t.Error("non-DNS record should not produce DNS metrics")
	}
}
