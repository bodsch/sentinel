package metrics

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
)

// TestNewRegistryExposesBuildInfo verifies the build-info gauge is present on a
// fresh registry and that the runtime collectors are not registered by default
// (keeping test/benchmark registries clean).
func TestNewRegistryExposesBuildInfo(t *testing.T) {
	reg := NewRegistry()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	names := gatheredNames(families)
	if !names["sentinel_build_info"] {
		t.Errorf("sentinel_build_info missing; got %v", keys(names))
	}
	if names["go_goroutines"] || names["process_cpu_seconds_total"] {
		t.Errorf("runtime collectors leaked into a bare registry: %v", keys(names))
	}
}

// TestRegisterRuntimeCollectors verifies the Go and process collectors expose
// their self-observability series. go_goroutines and process_cpu_seconds_total
// are reported on every supported platform (Linux and macOS), so they are safe,
// portable assertions.
func TestRegisterRuntimeCollectors(t *testing.T) {
	reg := NewRegistry()
	RegisterRuntimeCollectors(reg)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	names := gatheredNames(families)
	for _, want := range []string{"go_goroutines", "process_cpu_seconds_total"} {
		if !names[want] {
			t.Errorf("runtime metric %q missing after RegisterRuntimeCollectors; got %v", want, keys(names))
		}
	}
}

// TestRegisterRuntimeCollectorsIsOneShot verifies a second registration panics
// via MustRegister, surfacing a wiring bug rather than silently double-counting.
func TestRegisterRuntimeCollectorsIsOneShot(t *testing.T) {
	reg := NewRegistry()
	RegisterRuntimeCollectors(reg)

	defer func() {
		if recover() == nil {
			t.Error("expected a panic on duplicate runtime-collector registration")
		}
	}()
	RegisterRuntimeCollectors(reg)
}

// TestTimingGathererRecordsRenderCost verifies the timing gatherer registers
// sentinel_scrape_duration_seconds via the production constructor, reports 0 on
// the first gather (one scrape behind), and records a positive render time on the
// next. 1000 targets make a gather take well above clock resolution, so the
// > 0 check is deterministic.
func TestTimingGathererRecordsRenderCost(t *testing.T) {
	reg := NewRegistry()
	reg.MustRegister(NewProbeCollector(benchResults(1000), benchSkips(1000)))
	g := NewTimingGatherer(reg)

	const name = "sentinel_scrape_duration_seconds"

	first, err := g.Gather()
	if err != nil {
		t.Fatalf("first gather: %v", err)
	}
	if v, ok := gaugeValue(first, name); !ok {
		t.Fatalf("%s absent on first gather", name)
	} else if v != 0 {
		t.Errorf("first gather %s = %v, want exactly 0 (one scrape behind)", name, v)
	}

	second, err := g.Gather()
	if err != nil {
		t.Fatalf("second gather: %v", err)
	}
	if v, ok := gaugeValue(second, name); !ok {
		t.Fatalf("%s absent on second gather", name)
	} else if v <= 0 {
		t.Errorf("second gather %s = %v, want > 0 (previous gather's render time)", name, v)
	}
}

// gaugeValue extracts a single gauge value by metric-family name.
func gaugeValue(families []*dto.MetricFamily, name string) (float64, bool) {
	for _, f := range families {
		if f.GetName() == name && len(f.GetMetric()) > 0 {
			return f.GetMetric()[0].GetGauge().GetValue(), true
		}
	}
	return 0, false
}

// gatheredNames reduces a gathered metric family slice to a name set.
func gatheredNames(families []*dto.MetricFamily) map[string]bool {
	names := make(map[string]bool, len(families))
	for _, f := range families {
		names[f.GetName()] = true
	}
	return names
}

// keys returns the keys of a name set, for readable failure messages.
func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
