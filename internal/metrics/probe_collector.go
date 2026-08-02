package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/scheduler"
	"bodsch.me/sentinel/internal/store"
)

// ResultSource supplies the current probe results at scrape time.
type ResultSource interface {
	Snapshot() []store.Record
}

// SkipSource supplies per-target skip counters at scrape time.
type SkipSource interface {
	Stats() []scheduler.JobStat
}

// ProbeCollector exposes the protocol-agnostic probe state. It reads the result
// store and scheduler stats live on every scrape, so metrics always reflect the
// latest state with no in-process history.
type ProbeCollector struct {
	results ResultSource
	skips   SkipSource

	success     *prometheus.Desc
	duration    *prometheus.Desc
	lastSuccess *prometheus.Desc
	failureInfo *prometheus.Desc
	skipped     *prometheus.Desc
}

// NewProbeCollector builds a ProbeCollector over the given sources.
func NewProbeCollector(results ResultSource, skips SkipSource) *ProbeCollector {
	withReason := append(append([]string{}, BaseLabelNames...), "reason")
	return &ProbeCollector{
		results: results,
		skips:   skips,
		success: prometheus.NewDesc(
			Namespace+"_probe_success",
			"1 if the last probe succeeded, else 0.",
			BaseLabelNames, nil),
		duration: prometheus.NewDesc(
			Namespace+"_probe_duration_seconds",
			"Total duration of the last probe run.",
			BaseLabelNames, nil),
		lastSuccess: prometheus.NewDesc(
			Namespace+"_probe_last_success_timestamp_seconds",
			"Unix timestamp of the last successful probe.",
			BaseLabelNames, nil),
		failureInfo: prometheus.NewDesc(
			Namespace+"_probe_failure_info",
			"1 while the probe is failing; the reason label gives the cause. Absent on success.",
			withReason, nil),
		skipped: prometheus.NewDesc(
			Namespace+"_probe_skipped_total",
			"Number of probe runs skipped because the previous run was still in flight.",
			BaseLabelNames, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *ProbeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.success
	ch <- c.duration
	ch <- c.lastSuccess
	ch <- c.failureInfo
	ch <- c.skipped
}

// Collect implements prometheus.Collector.
func (c *ProbeCollector) Collect(ch chan<- prometheus.Metric) {
	for _, rec := range c.results.Snapshot() {
		labels := BaseLabelValues(rec)

		success := 0.0
		if rec.Result.Success {
			success = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.success, prometheus.GaugeValue, success, labels...)
		ch <- prometheus.MustNewConstMetric(c.duration, prometheus.GaugeValue, rec.Result.Duration.Seconds(), labels...)

		if !rec.LastSuccess.IsZero() {
			ch <- prometheus.MustNewConstMetric(c.lastSuccess, prometheus.GaugeValue, float64(rec.LastSuccess.Unix()), labels...)
		}

		// The failure_info series exists only while failing, so on recovery it
		// simply stops being emitted — no orphaned time series.
		if !rec.Result.Success {
			reasonLabels := append(append([]string{}, labels...), rec.Result.FailureReason.String())
			ch <- prometheus.MustNewConstMetric(c.failureInfo, prometheus.GaugeValue, 1, reasonLabels...)
		}
	}

	for _, stat := range c.skips.Stats() {
		labels := baseValues(stat.Name, stat.Type, stat.Labels)
		ch <- prometheus.MustNewConstMetric(c.skipped, prometheus.CounterValue, float64(stat.Skipped), labels...)
	}
}
