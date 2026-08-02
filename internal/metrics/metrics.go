// Package metrics exposes Sentinel's state as Prometheus metrics.
//
// The design (see the metrics spec) keeps the exporter itself protocol-agnostic:
// state is read live at scrape time from the result store via self-registering
// collectors. The generic ProbeCollector here handles success/duration/failure
// state common to all probes; protocol packages register their own collector for
// protocol-specific series (e.g. HTTP phase timings), so a new protocol needs no
// change to this package.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	dto "github.com/prometheus/client_model/go"

	"bodsch.me/sentinel/internal/store"
	"bodsch.me/sentinel/pkg/version"
)

// Namespace prefixes every Sentinel metric name.
const Namespace = "sentinel"

// BaseLabelNames is the fixed label set carried by every probe metric. The set
// is fixed (not derived from arbitrary tags) to keep cardinality bounded;
// unknown tags are rejected at config validation. Absent tags become empty
// label values, which keeps every series dimensionally consistent.
var BaseLabelNames = []string{"target", "type", "environment", "location", "service"}

// BaseLabelValues returns the base label values for a store record, in the same
// order as BaseLabelNames.
func BaseLabelValues(rec store.Record) []string {
	return baseValues(rec.Target, rec.Type, rec.Labels)
}

// baseValues builds the base label values from a target's identity.
func baseValues(name, typ string, labels map[string]string) []string {
	return []string{name, typ, labels["environment"], labels["location"], labels["service"]}
}

// NewRegistry creates a dedicated (non-default) registry and registers the
// build-info metric. Collectors are registered by the caller. A dedicated
// registry keeps tests isolated and avoids leaking the process/Go collectors
// unless explicitly added.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()

	buildInfo := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "build_info",
			Help:      "Build information. Always 1; the version/commit/go labels carry the data.",
		},
		[]string{"version", "commit", "go_version"},
	)
	info := version.Get()
	buildInfo.WithLabelValues(info.Version, info.Commit, info.GoVersion).Set(1)
	reg.MustRegister(buildInfo)

	return reg
}

// NewTimingGatherer wraps reg so the wall time of each Gather — the O(N) render
// cost of building all metric families, which excludes HTTP encoding and the
// network write to the scraper — is recorded into a newly registered
// sentinel_scrape_duration_seconds gauge. It returns a Gatherer for the metrics
// handler to serve in place of the bare registry.
//
// The duration is Set after Gather returns, so the exported value reflects the
// previous scrape (one scrape behind) — the conventional behaviour for a
// self-measuring metric and exact enough for sizing scrape_timeout. The value is
// the most recent scrape's render time; with overlapping scrapes it is
// approximate (a plain gauge is last-writer-wins).
//
// Parameters:
//   - reg: the registry to wrap and to register the gauge on.
//
// It panics via MustRegister if the gauge is already registered (a wiring bug).
func NewTimingGatherer(reg *prometheus.Registry) prometheus.Gatherer {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "scrape_duration_seconds",
		Help:      "Time to gather all metric series on the last scrape (render cost; O(N) in targets, excludes HTTP encoding and network). Size scrape_timeout above it.",
	})
	reg.MustRegister(g)
	return &timingGatherer{inner: reg, dur: g}
}

// timingGatherer records how long the wrapped Gatherer takes into dur.
type timingGatherer struct {
	inner prometheus.Gatherer
	dur   prometheus.Gauge
}

// Gather times the inner Gather and records it, exporting the previous scrape's
// render time on this one.
func (t *timingGatherer) Gather() ([]*dto.MetricFamily, error) {
	start := time.Now()
	mfs, err := t.inner.Gather()
	t.dur.Set(time.Since(start).Seconds())
	return mfs, err
}

// RegisterRuntimeCollectors adds the standard Go runtime and process collectors
// to reg, exposing self-observability for the Sentinel process itself:
// go_goroutines, go_memstats_*, go_gc_*, process_resident_memory_bytes,
// process_cpu_seconds_total, process_open_fds, and so on.
//
// It is deliberately kept out of NewRegistry so that unit tests and benchmarks
// get a clean, deterministic registry; production wires it in explicitly. The
// process collector reads OS-level counters; its coverage is platform-dependent.
// On Linux (the primary deployment target) it exposes the full set including
// process_resident_memory_bytes and process_virtual_memory_bytes. On macOS a
// subset is reported (process_cpu_seconds_total, process_open_fds,
// process_max_fds, process_start_time_seconds) while the resident/virtual memory
// gauges are absent; it registers without error either way, keeping builds and
// tests portable.
//
// Parameters:
//   - reg: the registry to register the runtime collectors on.
//
// It panics (via MustRegister) if a collector is already registered, which
// would indicate a wiring bug rather than a runtime condition.
func RegisterRuntimeCollectors(reg *prometheus.Registry) {
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}
