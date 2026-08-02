// Package server exposes Sentinel's operational HTTP surface: the Prometheus
// metrics endpoint plus liveness and readiness checks.
//
// Readiness reflects Sentinel's own state (configuration loaded and scheduler
// started), not the state of the monitored targets. Failing probes are a correct
// measurement, not an unready condition — otherwise an orchestrator would
// restart Sentinel exactly when it is most needed.
package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Options configures a Server.
type Options struct {
	// Addr is the listen address, e.g. ":8080".
	Addr string
	// Registry is the Prometheus registry served at /metrics.
	Registry *prometheus.Registry
	// Logger is used for serve errors. If nil, a discard logger is used.
	Logger *slog.Logger
}

// Server serves /metrics, /healthz and /readyz.
type Server struct {
	addr   string
	http   *http.Server
	logger *slog.Logger
	ready  atomic.Bool
}

// New builds a Server. The metrics endpoint serves the given registry.
func New(opts Options) *Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{addr: opts.Addr, logger: logger}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(opts.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)

	s.http = &http.Server{
		Addr:              opts.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// SetReady marks the server ready (or not). While not ready, /readyz returns 503.
func (s *Server) SetReady(ready bool) {
	s.ready.Store(ready)
}

// Start binds the listen address and serves in a background goroutine. It
// returns synchronously if the address cannot be bound, so a port conflict is a
// hard startup error. Serve errors after start are logged.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	go func() {
		if err := s.http.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("metrics server stopped", slog.Any("error", err))
		}
	}()
	return nil
}

// Shutdown gracefully stops the server, waiting up to ctx's deadline for
// in-flight requests (e.g. an ongoing scrape) to complete.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// Handler returns the request handler, for tests.
func (s *Server) Handler() http.Handler {
	return s.http.Handler
}

// handleHealthz is the liveness probe: 200 while the process is running.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleReadyz is the readiness probe: 200 once Sentinel is ready, else 503.
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if s.ready.Load() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte("not ready\n"))
}
