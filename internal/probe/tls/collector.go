package tls

import (
	"crypto/tls"
	"slices"
	"strconv"

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
// endpoint directly — the phases of getting there, plus the STARTTLS dialogue
// for targets that upgrade a plaintext connection.
type Collector struct {
	results resultSource

	dnsDuration       *prometheus.Desc
	connectDuration   *prometheus.Desc
	handshakeDuration *prometheus.Desc
	startTLSDuration  *prometheus.Desc

	versionSupported *prometheus.Desc
	cipherSupported  *prometheus.Desc
	insecureCount    *prometheus.Desc
	enumTimestamp    *prometheus.Desc
	enumComplete     *prometheus.Desc
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
		startTLSDuration:  desc("tls_starttls_duration_seconds", "Plaintext STARTTLS dialogue time of the TLS probe; present only for targets with tls.starttls."),

		versionSupported: prometheus.NewDesc(metrics.Namespace+"_tls_version_supported",
			"1 when the server accepted a handshake restricted to this TLS version, 0 when it refused; absent when unknown. Only with tls.enumerate.",
			append(slices.Clone(metrics.BaseLabelNames), "version"), nil),
		cipherSupported: prometheus.NewDesc(metrics.Namespace+"_tls_cipher_supported",
			"Present (value 1) for each cipher suite the server accepted; insecure follows crypto/tls's classification. Only with tls.enumerate.",
			append(slices.Clone(metrics.BaseLabelNames), "cipher", "insecure"), nil),
		insecureCount: desc("tls_insecure_ciphers_supported", "Number of accepted cipher suites classified as insecure. Only with tls.enumerate."),
		enumTimestamp: desc("tls_enumeration_timestamp_seconds", "When the last version and cipher-suite enumeration finished, as a Unix timestamp."),
		enumComplete:  desc("tls_enumeration_complete", "1 when every handshake of the last enumeration gave a definite answer, 0 when some timed out or could not connect."),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.dnsDuration
	ch <- c.connectDuration
	ch <- c.handshakeDuration
	ch <- c.startTLSDuration
	ch <- c.versionSupported
	ch <- c.cipherSupported
	ch <- c.insecureCount
	ch <- c.enumTimestamp
	ch <- c.enumComplete
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
		d, ok := rec.Result.Diagnostics.(*Diagnostics)
		if !ok || d == nil {
			continue
		}
		if d.StartTLS != StartTLSNone {
			gauge(c.startTLSDuration, d.StartTLSDuration.Seconds())
		}
		if e := d.Enumeration; e != nil {
			c.collectEnumeration(ch, labels, e)
		}
	}
}

// collectEnumeration emits the enumeration series of one target.
func (c *Collector) collectEnumeration(ch chan<- prometheus.Metric, labels []string, e *Enumeration) {
	gauge := func(d *prometheus.Desc, v float64, lv []string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, lv...)
	}
	for _, v := range e.Versions {
		if !v.Known {
			continue // unknown is not "unsupported"
		}
		value := 0.0
		if v.Supported {
			value = 1
		}
		gauge(c.versionSupported, value, append(slices.Clone(labels), tls.VersionName(v.Version)))
	}
	for _, cs := range e.Ciphers {
		if cs.Known && cs.Supported {
			gauge(c.cipherSupported, 1, append(slices.Clone(labels), cs.Name, strconv.FormatBool(cs.Insecure)))
		}
	}
	gauge(c.insecureCount, float64(len(e.InsecureSupported())), labels)
	gauge(c.enumTimestamp, float64(e.At.Unix()), labels)
	complete := 0.0
	if e.Complete {
		complete = 1
	}
	gauge(c.enumComplete, complete, labels)
}
