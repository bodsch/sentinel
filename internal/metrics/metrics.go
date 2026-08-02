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
	"github.com/prometheus/client_golang/prometheus"

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
