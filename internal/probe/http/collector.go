package http

import (
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/metrics"
	"bodsch.me/sentinel/internal/store"
)

// resultSource supplies current probe results at scrape time.
type resultSource interface {
	Snapshot() []store.Record
}

// Collector exposes the HTTP-specific metrics (phase timings, status code,
// redirect count and TLS certificate diagnostics). It lives in the http package
// — not the metrics package — so a new protocol can add its own collector
// without the exporter needing to know about it (self-registering collectors).
type Collector struct {
	results resultSource

	statusCode  *prometheus.Desc
	dnsDuration *prometheus.Desc
	tcpDuration *prometheus.Desc
	tlsDuration *prometheus.Desc
	ttfb        *prometheus.Desc
	download    *prometheus.Desc
	redirects   *prometheus.Desc
	certExpiry  *prometheus.Desc
	certRemain  *prometheus.Desc
	certValid   *prometheus.Desc
}

// NewCollector builds the HTTP metrics collector over the given result source.
func NewCollector(results resultSource) *Collector {
	base := metrics.BaseLabelNames
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(metrics.Namespace+"_"+name, help, base, nil)
	}
	return &Collector{
		results:     results,
		statusCode:  desc("http_status_code", "HTTP status code of the final response."),
		dnsDuration: desc("http_dns_duration_seconds", "DNS resolution time of the final hop."),
		tcpDuration: desc("http_tcp_connect_duration_seconds", "TCP connect time of the final hop."),
		tlsDuration: desc("http_tls_handshake_duration_seconds", "TLS handshake time of the final hop."),
		ttfb:        desc("http_ttfb_seconds", "Time to first response byte of the final hop."),
		download:    desc("http_download_duration_seconds", "Response body download time of the final hop."),
		redirects:   desc("http_redirects", "Number of redirects followed on the last probe."),
		certExpiry:  desc("tls_certificate_expiry_timestamp_seconds", "Unix timestamp when the leaf certificate expires."),
		certRemain:  desc("tls_certificate_remaining_days", "Whole days until the leaf certificate expires; negative if expired."),
		certValid:   desc("tls_certificate_valid", "1 if the certificate passed Sentinel's checks, else 0."),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.statusCode
	ch <- c.dnsDuration
	ch <- c.tcpDuration
	ch <- c.tlsDuration
	ch <- c.ttfb
	ch <- c.download
	ch <- c.redirects
	ch <- c.certExpiry
	ch <- c.certRemain
	ch <- c.certValid
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, rec := range c.results.Snapshot() {
		if rec.Type != ProbeType {
			continue
		}
		diag, ok := rec.Result.Diagnostics.(*Diagnostics)
		if !ok || diag == nil {
			continue
		}
		labels := metrics.BaseLabelValues(rec)
		t := rec.Result.Timings

		gauge := func(d *prometheus.Desc, v float64) {
			ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
		}

		if diag.StatusCode > 0 {
			gauge(c.statusCode, float64(diag.StatusCode))
		}
		gauge(c.dnsDuration, t.DNS.Seconds())
		gauge(c.tcpDuration, t.Connect.Seconds())
		gauge(c.tlsDuration, t.TLS.Seconds())
		gauge(c.ttfb, t.TTFB.Seconds())
		gauge(c.download, t.Download.Seconds())
		gauge(c.redirects, float64(len(diag.Redirects)))

		if diag.TLS != nil {
			gauge(c.certExpiry, float64(diag.TLS.ExpiresAt.Unix()))
			gauge(c.certRemain, float64(diag.TLS.RemainingDays))
			valid := 0.0
			if diag.TLS.Valid {
				valid = 1.0
			}
			gauge(c.certValid, valid)
		}
	}
}
