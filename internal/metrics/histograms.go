package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/store"
)

// LatencyBuckets is the shared histogram bucket set for latency metrics, in
// seconds. It spans 5 ms to 10 s, covering fast local responses through slow
// near-timeout runs. Protocol packages reuse it so all latency histograms share
// one bucket layout.
var LatencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// ProbeDurationObserver records the total run duration of successful probes into
// the sentinel_probe_duration_seconds histogram. It is fed at probe time (via the
// scheduler's Observer hook), replacing the former last-value gauge of the same
// name: because Sentinel probes more often than Prometheus scrapes, a scrape-time
// gauge only ever exposes the last probe, while the histogram captures every one.
//
// It is protocol-agnostic — every probe type contributes, distinguished by the
// "type" label.
type ProbeDurationObserver struct {
	hist *prometheus.HistogramVec
}

// NewProbeDurationObserver creates the histogram, registers it on reg, and
// returns the observer for the scheduler to feed. It panics via MustRegister if
// a metric with the same name is already registered (a wiring bug).
//
// Parameters:
//   - reg: the registry to register the histogram on.
func NewProbeDurationObserver(reg *prometheus.Registry) *ProbeDurationObserver {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "probe_duration_seconds",
		Help:      "Distribution of total probe run duration for successful probes, in seconds.",
		Buckets:   LatencyBuckets,
	}, BaseLabelNames)
	reg.MustRegister(h)
	return &ProbeDurationObserver{hist: h}
}

// Observe records a successful probe's total duration. Failed probes are skipped
// so timeouts and fast failures do not distort the latency distribution — a
// probe's failure state is already carried by sentinel_probe_success.
func (o *ProbeDurationObserver) Observe(rec store.Record) {
	if !rec.Result.Success {
		return
	}
	o.hist.WithLabelValues(BaseLabelValues(rec)...).Observe(rec.Result.Duration.Seconds())
}
