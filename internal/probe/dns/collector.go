package dns

import (
	"slices"

	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/metrics"
	"bodsch.me/sentinel/internal/store"
)

// resultSource supplies current probe results at scrape time.
type resultSource interface {
	Snapshot() []store.Record
}

// Collector exposes the DNS-specific metrics (query duration, response code and
// answer count), plus per-resolver series and the consistency verdict for
// targets that compare several resolvers. Like the HTTP collector it lives in its own protocol package so
// adding DNS required no change to the metrics exporter.
type Collector struct {
	results resultSource

	queryDuration *prometheus.Desc
	responseCode  *prometheus.Desc
	answerCount   *prometheus.Desc

	resolverDuration *prometheus.Desc
	resolverCode     *prometheus.Desc
	resolverAnswers  *prometheus.Desc
	consistent       *prometheus.Desc
}

// NewCollector builds the DNS metrics collector over the given result source.
func NewCollector(results resultSource) *Collector {
	base := metrics.BaseLabelNames
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(metrics.Namespace+"_"+name, help, base, nil)
	}
	perResolver := append(slices.Clone(base), "resolver")
	resolverDesc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(metrics.Namespace+"_"+name, help, perResolver, nil)
	}
	return &Collector{
		results:       results,
		queryDuration: desc("dns_query_duration_seconds", "Duration of the DNS query."),
		responseCode:  desc("dns_response_code", "DNS response code (RCODE); 0 is NOERROR."),
		answerCount:   desc("dns_answer_count", "Number of answer records of the queried type."),

		resolverDuration: resolverDesc("dns_resolver_query_duration_seconds", "Duration of the DNS query against one resolver; only for targets with several resolvers."),
		resolverCode:     resolverDesc("dns_resolver_response_code", "DNS response code (RCODE) from one resolver; -1 when it produced no response."),
		resolverAnswers:  resolverDesc("dns_resolver_answer_count", "Number of answer records of the queried type from one resolver."),
		consistent:       desc("dns_answers_consistent", "1 when all resolvers of a multi-resolver target returned the same answer set, 0 otherwise."),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.queryDuration
	ch <- c.responseCode
	ch <- c.answerCount
	ch <- c.resolverDuration
	ch <- c.resolverCode
	ch <- c.resolverAnswers
	ch <- c.consistent
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

		if len(diag.Resolvers) == 0 {
			continue
		}
		consistent := 0.0
		if diag.Consistent {
			consistent = 1
		}
		ch <- prometheus.MustNewConstMetric(c.consistent, prometheus.GaugeValue, consistent, labels...)
		for _, r := range diag.Resolvers {
			rl := append(slices.Clone(labels), r.Server)
			code := float64(r.ResponseCode)
			if r.err != nil {
				code = -1
			}
			ch <- prometheus.MustNewConstMetric(c.resolverDuration, prometheus.GaugeValue, r.Duration.Seconds(), rl...)
			ch <- prometheus.MustNewConstMetric(c.resolverCode, prometheus.GaugeValue, code, rl...)
			ch <- prometheus.MustNewConstMetric(c.resolverAnswers, prometheus.GaugeValue, float64(len(r.Answers)), rl...)
		}
	}
}
