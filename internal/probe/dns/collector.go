package dns

import (
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/metrics"
	"bodsch.me/sentinel/internal/store"
)

// resultSource supplies current probe results at scrape time.
type resultSource interface {
	Snapshot() []store.Record
}

// Collector exposes the DNS-specific metrics (query duration, response code and
// answer count). Like the HTTP collector it lives in its own protocol package so
// adding DNS required no change to the metrics exporter.
type Collector struct {
	results resultSource

	queryDuration *prometheus.Desc
	responseCode  *prometheus.Desc
	answerCount   *prometheus.Desc
}

// NewCollector builds the DNS metrics collector over the given result source.
func NewCollector(results resultSource) *Collector {
	base := metrics.BaseLabelNames
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(metrics.Namespace+"_"+name, help, base, nil)
	}
	return &Collector{
		results:       results,
		queryDuration: desc("dns_query_duration_seconds", "Duration of the DNS query."),
		responseCode:  desc("dns_response_code", "DNS response code (RCODE); 0 is NOERROR."),
		answerCount:   desc("dns_answer_count", "Number of answer records of the queried type."),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.queryDuration
	ch <- c.responseCode
	ch <- c.answerCount
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	for _, rec := range c.results.Snapshot() {
		if rec.Type != ProbeType {
			continue
		}
		labels := metrics.BaseLabelValues(rec)

		ch <- prometheus.MustNewConstMetric(c.queryDuration, prometheus.GaugeValue, rec.Result.Timings.DNS.Seconds(), labels...)

		diag, ok := rec.Result.Diagnostics.(*Diagnostics)
		if !ok || diag == nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.responseCode, prometheus.GaugeValue, float64(diag.ResponseCode), labels...)
		ch <- prometheus.MustNewConstMetric(c.answerCount, prometheus.GaugeValue, float64(diag.AnswerCount), labels...)
	}
}
