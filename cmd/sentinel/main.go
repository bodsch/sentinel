// Command sentinel is the Sentinel synthetic monitoring daemon: it continuously
// probes the configured HTTP targets and exposes their state to Prometheus.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"bodsch.me/sentinel/internal/clock"
	"bodsch.me/sentinel/internal/config"
	"bodsch.me/sentinel/internal/logging"
	"bodsch.me/sentinel/internal/metrics"
	"bodsch.me/sentinel/internal/probe"
	dnsprobe "bodsch.me/sentinel/internal/probe/dns"
	httpprobe "bodsch.me/sentinel/internal/probe/http"
	tcpprobe "bodsch.me/sentinel/internal/probe/tcp"
	"bodsch.me/sentinel/internal/scheduler"
	"bodsch.me/sentinel/internal/server"
	"bodsch.me/sentinel/internal/store"
	"bodsch.me/sentinel/pkg/version"
)

// exit codes
const (
	exitOK    = 0
	exitUsage = 2
	exitError = 1
)

// shutdownTimeout bounds the graceful drain of in-flight probes and the metrics
// server on shutdown.
const shutdownTimeout = 10 * time.Second

// options holds the parsed command-line options.
type options struct {
	configPath  string
	validate    bool
	showVersion bool
	logLevel    string
	logFormat   string
	listen      string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses arguments and dispatches. It returns a process exit code. Splitting
// this out of main keeps it testable.
func run(args []string, stdout, stderr *os.File) int {
	cfg, code, done := parseFlags(args, stderr)
	if done {
		return code
	}

	if cfg.showVersion {
		fmt.Fprintln(stdout, version.Get().String())
		return exitOK
	}

	level, err := logging.ParseLevel(cfg.logLevel)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	format, err := logging.ParseFormat(cfg.logFormat)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	logger := logging.New(stderr, logging.Options{Level: level, Format: format})

	if cfg.configPath == "" {
		if p := os.Getenv("SENTINEL_CONFIG"); p != "" {
			cfg.configPath = p
		}
	}
	if cfg.configPath == "" {
		fmt.Fprintln(stderr, "sentinel: no config file given (use --config or SENTINEL_CONFIG)")
		return exitUsage
	}

	// Load and validate the configuration. This is fail-fast: an invalid config
	// stops the process rather than starting with a partial configuration.
	loaded, err := config.Load(cfg.configPath)
	if err != nil {
		// --validate is a CI/GitOps dry-run: report every problem and exit
		// non-zero without starting anything. A normal start fails the same way.
		fmt.Fprintln(stderr, err)
		return exitError
	}

	if cfg.validate {
		fmt.Fprintf(stdout, "config OK: %d target(s) in %s\n", len(loaded.Targets), cfg.configPath)
		return exitOK
	}

	logger.Info("sentinel starting",
		"version", version.Version,
		"commit", version.Commit,
		"config", cfg.configPath,
		"targets", len(loaded.Targets),
		"listen", cfg.listen,
	)

	return serve(cfg, loaded, logger)
}

// serve wires the runtime — store, scheduler, collectors, metrics server — runs
// it, and blocks until a termination signal triggers a graceful shutdown.
func serve(cfg options, loaded *config.Config, logger *slog.Logger) int {
	st := store.New()
	reg := metrics.NewRegistry()

	// Observation-based metrics: latency histograms fed at probe time (they
	// capture every probe, unlike the scrape-time state gauges). They register
	// their own histograms on reg and are notified by the scheduler.
	sched := scheduler.New(scheduler.Options{
		Clock: clock.Real{},
		Store: st,
		Observer: scheduler.Observers{
			metrics.NewProbeDurationObserver(reg),
			httpprobe.NewTTFBObserver(reg),
		},
		Logger: logger,
	})

	for i := range loaded.Targets {
		target := loaded.Targets[i]
		prober, ptype, err := buildProber(target)
		if err != nil {
			logger.Error("building probe", slog.String("target", target.Name), slog.Any("error", err))
			return exitError
		}
		spec := scheduler.JobSpec{
			Name:     target.Name,
			Type:     ptype,
			Interval: target.ResolvedInterval(),
			Labels:   target.Tags,
			Prober:   prober,
		}
		if err := sched.Add(spec); err != nil {
			logger.Error("registering target", slog.String("target", target.Name), slog.Any("error", err))
			return exitError
		}
	}

	// Register collectors: the generic probe collector plus each protocol's own.
	reg.MustRegister(metrics.NewProbeCollector(st, sched))
	reg.MustRegister(httpprobe.NewCollector(st))
	reg.MustRegister(dnsprobe.NewCollector(st))
	reg.MustRegister(tcpprobe.NewCollector(st))

	// Expose the process's own runtime health (goroutines, heap, GC, CPU, FDs).
	metrics.RegisterRuntimeCollectors(reg)

	// Serve through a timing gatherer so the per-scrape render cost is recorded
	// (sentinel_scrape_duration_seconds) and scrape_timeout can be sized to it.
	gatherer := metrics.NewTimingGatherer(reg)

	srv := server.New(server.Options{
		Addr:     cfg.listen,
		Gatherer: gatherer,
		Logger:   logger,
	})
	if err := srv.Start(); err != nil {
		logger.Error("starting metrics server", slog.Any("error", err))
		return exitError
	}

	// Cancel the root context on SIGINT/SIGTERM. The scheduler watches this
	// context; cancellation stops new probes and drains in-flight ones.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	schedulerDone := make(chan struct{})
	go func() {
		sched.Run(ctx)
		close(schedulerDone)
	}()

	srv.SetReady(true)
	logger.Info("sentinel ready", slog.Int("targets", len(loaded.Targets)), slog.String("listen", cfg.listen))

	<-ctx.Done()
	logger.Info("shutting down")

	// Bound the scheduler drain by shutdownTimeout.
	select {
	case <-schedulerDone:
	case <-time.After(shutdownTimeout):
		logger.Warn("scheduler drain timed out", slog.Duration("timeout", shutdownTimeout))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("metrics server shutdown", slog.Any("error", err))
	}

	logger.Info("sentinel stopped")
	return exitOK
}

// buildProber constructs the prober for a target based on which protocol block
// is present, returning the prober and its type label.
func buildProber(target config.Target) (probe.Prober, string, error) {
	switch {
	case target.HTTP != nil:
		p, err := httpprobe.New(httpOptions(target))
		return p, httpprobe.ProbeType, err
	case target.DNS != nil:
		p, err := dnsprobe.New(dnsOptions(target))
		return p, dnsprobe.ProbeType, err
	case target.TCP != nil:
		p, err := tcpprobe.New(tcpOptions(target))
		return p, tcpprobe.ProbeType, err
	default:
		return nil, "", fmt.Errorf("target %q has no protocol block", target.Name)
	}
}

// tcpOptions maps a resolved config target to TCP prober options.
func tcpOptions(target config.Target) tcpprobe.Options {
	tc := target.TCP
	return tcpprobe.Options{
		Name:        target.Name,
		Address:     tc.Address,
		BannerRegex: tc.Expect.BannerRegex,
		Timeout:     target.ResolvedTimeout(),
	}
}

// dnsOptions maps a resolved config target to DNS prober options.
func dnsOptions(target config.Target) dnsprobe.Options {
	d := target.DNS
	return dnsprobe.Options{
		Name:     target.Name,
		Server:   d.Server,
		Query:    d.Query,
		Type:     d.Type,
		Expected: d.Expected,
		Timeout:  target.ResolvedTimeout(),
	}
}

// httpOptions maps a resolved config target to HTTP prober options.
func httpOptions(target config.Target) httpprobe.Options {
	h := target.HTTP
	opts := httpprobe.Options{
		Name:            target.Name,
		Method:          h.Method,
		URL:             h.URL,
		Timeout:         target.ResolvedTimeout(),
		FollowRedirects: h.ResolvedFollowRedirects(),
		MaxRedirects:    h.ResolvedMaxRedirects(),
		MaxBodyBytes:    h.ResolvedMaxBodyBytes(),
		ExpectStatus:    h.Expect.ExpectedStatus(),
		BodyRegex:       h.Expect.BodyRegex,
		Headers:         h.Expect.Headers,
		RequestHeaders:  h.Headers,
		BearerToken:     h.BearerToken,
		Body:            h.Body,
	}
	if h.BasicAuth != nil {
		opts.BasicAuthUser = h.BasicAuth.Username
		opts.BasicAuthPass = h.BasicAuth.Password
	}
	return opts
}

// parseFlags parses args into a config. The done flag is true when the process
// should exit immediately with the returned code (e.g. -h or a parse error).
func parseFlags(args []string, stderr *os.File) (cfg options, code int, done bool) {
	fs := flag.NewFlagSet("sentinel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.configPath, "config", "", "path to the YAML config file (env: SENTINEL_CONFIG)")
	fs.BoolVar(&cfg.validate, "validate", false, "load and validate the config, then exit (no probes started)")
	fs.BoolVar(&cfg.showVersion, "version", false, "print version information and exit")
	fs.StringVar(&cfg.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.StringVar(&cfg.logFormat, "log-format", "json", "log format: json, text")
	fs.StringVar(&cfg.listen, "listen", ":8080", "HTTP listen address for /metrics, /healthz, /readyz")

	if err := fs.Parse(args); err != nil {
		// flag already printed the error / usage.
		return cfg, exitUsage, true
	}
	return cfg, exitOK, false
}
