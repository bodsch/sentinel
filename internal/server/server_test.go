package server

import (
	"context"
	"io"
	"net"
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
	return New(Options{Addr: ":0", Gatherer: reg})
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
	s := New(Options{Addr: "127.0.0.1:0", Gatherer: reg})
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

// TestStartFailsOnAPortConflict is the promise in Start's doc comment: the bind
// happens synchronously, so a taken port is a hard startup error.
//
// It matters because of what serve() does with the return value — it logs and
// exits non-zero. If Start instead handed the bind to the background goroutine
// and returned nil, Sentinel would carry on: it would register collectors, mark
// itself ready, and probe every target on schedule, while /metrics was never
// reachable. Prometheus would report the exporter as down, which reads like a
// network problem rather than a configuration one, and the process would keep
// restarting into the same conflict without ever saying which port was taken.
//
// A real second listener is used rather than a stub: the point is that the OS
// refuses the bind, which no injected error can demonstrate.
func TestStartFailsOnAPortConflict(t *testing.T) {
	t.Parallel()

	// Occupy a port, then ask a Server for the very same address.
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupying a port: %v", err)
	}
	defer func() { _ = blocker.Close() }()
	addr := blocker.Addr().String()

	s := New(Options{Addr: addr, Gatherer: prometheus.NewRegistry()})
	startErr := s.Start()
	if startErr == nil {
		// Do not leave a serving goroutine behind if the promise is broken.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
		t.Fatalf("Start on the already-bound address %s returned nil; the daemon would mark "+
			"itself ready and probe on schedule while /metrics was never reachable", addr)
	}
	if !strings.Contains(startErr.Error(), addr) {
		t.Errorf("Start error %q does not name the address %s; an operator cannot tell which "+
			"port is taken", startErr, addr)
	}
}

// TestStartIsIdempotentlySafeToShutdown covers the shutdown side of the same
// path: Shutdown on a server that never started must not block or panic.
// serve() defers the shutdown unconditionally, so if a later refactor made
// Start's failure non-fatal, this is the call that would hang the process during
// termination instead of letting it exit.
func TestStartIsIdempotentlySafeToShutdown(t *testing.T) {
	t.Parallel()

	s := New(Options{Addr: "127.0.0.1:0", Gatherer: prometheus.NewRegistry()})

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		done <- s.Shutdown(ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Shutdown on a never-started server = %v, want nil", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("Shutdown blocked on a server that was never started; process termination " +
			"would hang instead of exiting")
	}
}

// TestUnknownPathIs404 pins the operational surface to exactly the three
// documented endpoints. A catch-all that answered 200 on any path would make an
// orchestrator's health check pass against a typo'd path (/health instead of
// /healthz), so a genuinely unready Sentinel would be routed traffic.
func TestUnknownPathIs404(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)

	for _, path := range []string{"/", "/health", "/ready", "/metric", "/metrics/extra", "/healthz/"} {
		if code, _ := do(t, s, path); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (only /metrics, /healthz and /readyz exist)", path, code)
		}
	}

	// A dot-dot path is normalised by http.ServeMux before any handler runs, so
	// it redirects to the canonical path rather than reaching /metrics directly.
	// Asserting 404 here would be asserting against the standard library, not
	// against this package; what matters is that it never serves the target of
	// the traversal in place.
	if code, _ := do(t, s, "/../metrics"); code != http.StatusTemporaryRedirect && code != http.StatusMovedPermanently {
		t.Errorf("GET /../metrics = %d, want a redirect to the cleaned path", code)
	}
}
