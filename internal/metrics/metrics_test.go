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
