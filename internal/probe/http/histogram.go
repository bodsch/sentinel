package http

import (
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/metrics"
	"bodsch.me/sentinel/internal/store"
)

// TTFBObserver records the time-to-first-byte of successful HTTP probes into the
// sentinel_http_ttfb_seconds histogram, fed at probe time via the scheduler's
// Observer hook. It replaces the former last-value gauge of the same name so the
// distribution captures every probe, not just the last one seen at scrape time.
//
// Like the HTTP collector, it lives in the http package (not metrics) so the
// exporter core stays protocol-agnostic.
type TTFBObserver struct {
	hist *prometheus.HistogramVec
}

// NewTTFBObserver creates the histogram, registers it on reg, and returns the
// observer for the scheduler to feed. It panics via MustRegister if a metric
// with the same name is already registered (a wiring bug).
//
// Parameters:
//   - reg: the registry to register the histogram on.
func NewTTFBObserver(reg *prometheus.Registry) *TTFBObserver {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.Namespace,
		Name:      "http_ttfb_seconds",
		Help:      "Distribution of HTTP time-to-first-byte for successful probes, in seconds.",
		Buckets:   metrics.LatencyBuckets,
	}, metrics.BaseLabelNames)
	reg.MustRegister(h)
	return &TTFBObserver{hist: h}
}

// Observe records the TTFB of a successful HTTP probe. Non-HTTP records, failed
// probes, and runs with no measured first byte (TTFB <= 0) are skipped so the
// distribution reflects only real server-response latencies.
func (o *TTFBObserver) Observe(rec store.Record) {
	if rec.Type != ProbeType || !rec.Result.Success {
		return
	}
	ttfb := rec.Result.Timings.TTFB
	if ttfb <= 0 {
		return
	}
	o.hist.WithLabelValues(metrics.BaseLabelValues(rec)...).Observe(ttfb.Seconds())
}
