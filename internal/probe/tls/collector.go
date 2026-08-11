package tls

import (
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/metrics"
	"bodsch.me/sentinel/internal/store"
)

// resultSource supplies current probe results at scrape time.
type resultSource interface {
	Snapshot() []store.Record
}

// Collector exposes the TLS probe's phase timings.
//
// The certificate, chain and OCSP series are not emitted here: they come from
// internal/tlsdiag's collector, which serves every probe whose diagnostics carry
// TLS information. This collector only adds what is specific to dialling a TLS
// endpoint directly — the three phases of getting there.
type Collector struct {
	results resultSource

	dnsDuration       *prometheus.Desc
	connectDuration   *prometheus.Desc
	handshakeDuration *prometheus.Desc
}

// NewCollector builds the TLS probe metrics collector over the given result
// source.
func NewCollector(results resultSource) *Collector {
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(metrics.Namespace+"_"+name, help, metrics.BaseLabelNames, nil)
	}
	return &Collector{
		results:           results,
		dnsDuration:       desc("tls_dns_duration_seconds", "Name resolution time of the TLS probe."),
		connectDuration:   desc("tls_connect_duration_seconds", "TCP connection establishment time of the TLS probe."),
		handshakeDuration: desc("tls_handshake_duration_seconds", "TLS handshake time of the TLS probe."),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.dnsDuration
	ch <- c.connectDuration
	ch <- c.handshakeDuration
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, rec := range c.results.Snapshot() {
		if rec.Type != ProbeType {
			continue
		}
		labels := metrics.BaseLabelValues(rec)
		t := rec.Result.Timings

		gauge := func(d *prometheus.Desc, v float64) {
			ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
		}
		gauge(c.dnsDuration, t.DNS.Seconds())
		gauge(c.connectDuration, t.Connect.Seconds())
		gauge(c.handshakeDuration, t.TLS.Seconds())
	}
}
