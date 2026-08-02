package tcp

import (
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/metrics"
	"bodsch.me/sentinel/internal/store"
)

// resultSource supplies current probe results at scrape time.
type resultSource interface {
	Snapshot() []store.Record
}

// Collector exposes the TCP-specific connect-duration metric. Availability is
// already covered by the generic sentinel_probe_success, so it is not repeated
// here. Like the other protocol collectors it lives in its own package, so
// adding TCP needed no change to the metrics exporter.
type Collector struct {
	results    resultSource
	connectDur *prometheus.Desc
}

// NewCollector builds the TCP metrics collector over the given result source.
func NewCollector(results resultSource) *Collector {
	return &Collector{
		results: results,
		connectDur: prometheus.NewDesc(
			metrics.Namespace+"_tcp_connect_duration_seconds",
			"TCP connection establishment time in seconds (includes name resolution).",
			metrics.BaseLabelNames, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.connectDur
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, rec := range c.results.Snapshot() {
		if rec.Type != ProbeType {
			continue
		}
		labels := metrics.BaseLabelValues(rec)
		ch <- prometheus.MustNewConstMetric(c.connectDur, prometheus.GaugeValue, rec.Result.Timings.Connect.Seconds(), labels...)
	}
}
