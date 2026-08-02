package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	reg := prometheus.NewRegistry()
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "sentinel_test_metric", Help: "test"})
	g.Set(1)
	reg.MustRegister(g)
	return New(Options{Addr: ":0", Registry: reg})
}

func do(t *testing.T, s *Server, path string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	s.Handler().ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, string(body)
}

func TestHealthzAlwaysOK(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	if code, _ := do(t, s, "/healthz"); code != http.StatusOK {
		t.Errorf("healthz = %d, want 200", code)
	}
}

func TestReadyzReflectsReadiness(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)

	if code, _ := do(t, s, "/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("readyz before ready = %d, want 503", code)
	}

	s.SetReady(true)
	if code, body := do(t, s, "/readyz"); code != http.StatusOK || !strings.Contains(body, "ready") {
		t.Errorf("readyz after ready = %d %q, want 200 ready", code, body)
	}

	s.SetReady(false)
	if code, _ := do(t, s, "/readyz"); code != http.StatusServiceUnavailable {
		t.Errorf("readyz after unready = %d, want 503", code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	code, body := do(t, s, "/metrics")
	if code != http.StatusOK {
		t.Fatalf("metrics = %d, want 200", code)
	}
	if !strings.Contains(body, "sentinel_test_metric") {
		t.Errorf("metrics body missing the registered metric:\n%s", body)
	}
}

func TestStartAndShutdown(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	s := New(Options{Addr: "127.0.0.1:0", Registry: reg})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}
