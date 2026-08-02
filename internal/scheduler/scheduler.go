// Package scheduler drives probe execution. Each target runs on its own ticker
// (jittered to spread load); actual probe execution passes through a global
// semaphore that bounds how many probes run at once. A target never overlaps
// itself: if a tick fires while the previous run is still in flight, the tick is
// skipped and counted rather than queued.
//
// The scheduler is decoupled from the config and protocol packages: the caller
// builds a probe.Prober per target and registers it via Add.
package scheduler

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"bodsch.me/sentinel/internal/clock"
	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

// defaultConcurrency bounds simultaneous probes when Options.Concurrency is unset.
const defaultConcurrency = 50

// maxInitialDelay caps the jittered delay before a target's first probe, so a
// long-interval target still produces a first result promptly after startup
// while short intervals keep their full-interval load spreading.
const maxInitialDelay = 10 * time.Second

// Observer is notified of every completed probe result, at probe time. It is the
// write path for metrics that accumulate observations (e.g. latency histograms),
// which — unlike the scrape-time state collectors — must be fed as each probe
// finishes so they capture every probe, not just the one visible at scrape time.
// Implementations must be safe for concurrent use and must not block.
type Observer interface {
	Observe(store.Record)
}

// Observers fans a single Observe call out to several Observers, in order.
type Observers []Observer

// Observe forwards the record to every observer.
func (o Observers) Observe(r store.Record) {
	for _, obs := range o {
		obs.Observe(r)
	}
}

// Options configures a Scheduler.
type Options struct {
	// Clock supplies time; use clock.Real in production, a fake in tests.
	Clock clock.Clock
	// Store receives probe results.
	Store *store.Store
	// Observer, if non-nil, is notified of each completed (stored) probe result.
	// Results discarded during shutdown are not observed.
	Observer Observer
	// Concurrency is the maximum number of probes running at once. Values <= 0
	// use defaultConcurrency.
	Concurrency int
	// Logger is used for per-probe logging. If nil, a discard logger is used.
	Logger *slog.Logger
}

// JobSpec registers one target with the scheduler.
type JobSpec struct {
	// Name is the target name (result store primary key).
	Name string
	// Type is the probe protocol (e.g. "http"), used as a metric label.
	Type string
	// Interval is how often the target is probed.
	Interval time.Duration
	// Labels are the static label tags for this target.
	Labels map[string]string
	// Prober executes the check.
	Prober probe.Prober
}

// job is the scheduler's internal per-target state.
type job struct {
	spec    JobSpec
	running atomic.Bool
	skipped atomic.Int64
}

// Scheduler runs probes for a set of targets.
type Scheduler struct {
	clock    clock.Clock
	store    *store.Store
	observer Observer
	sem      chan struct{}
	logger   *slog.Logger
	jobs     []*job
	wg       sync.WaitGroup
}

// New creates a Scheduler from opts.
func New(opts Options) *Scheduler {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	clk := opts.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	return &Scheduler{
		clock:    clk,
		store:    opts.Store,
		observer: opts.Observer,
		sem:      make(chan struct{}, concurrency),
		logger:   logger,
	}
}

// Add registers a target. It must be called before Run. It returns an error for
// an invalid spec (empty name, non-positive interval, or nil prober) so a
// misconfigured job is rejected at wiring time rather than crashing the
// scheduler goroutine later. (Production configs are already validated, but the
// scheduler does not assume its caller has done so.)
func (s *Scheduler) Add(spec JobSpec) error {
	if spec.Name == "" {
		return fmt.Errorf("scheduler: job has an empty name")
	}
	if spec.Interval <= 0 {
		return fmt.Errorf("scheduler: job %q has a non-positive interval %v", spec.Name, spec.Interval)
	}
	if spec.Prober == nil {
		return fmt.Errorf("scheduler: job %q has a nil prober", spec.Name)
	}
	s.jobs = append(s.jobs, &job{spec: spec})
	return nil
}

// Run starts a ticker goroutine per target and blocks until ctx is cancelled,
// after which it waits for all in-flight probes to finish (a graceful drain).
// In-flight results produced after cancellation are discarded, not stored.
func (s *Scheduler) Run(ctx context.Context) {
	for _, j := range s.jobs {
		s.wg.Add(1)
		go s.runJob(ctx, j)
	}
	<-ctx.Done()
	s.wg.Wait()
}

// runJob drives one target: an initial jittered delay, an immediate first probe,
// then a probe on every interval tick until ctx is cancelled.
func (s *Scheduler) runJob(ctx context.Context, j *job) {
	defer s.wg.Done()

	// Initial jitter spreads targets out so they do not all fire together, but
	// is capped so a long-interval target is still probed soon after startup.
	select {
	case <-ctx.Done():
		return
	case <-s.clock.After(initialDelay(j.spec.Name, j.spec.Interval)):
	}

	s.tick(ctx, j)

	ticker := s.clock.NewTicker(j.spec.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			s.tick(ctx, j)
		}
	}
}

// tick starts one probe run unless the previous run is still in flight, in which
// case it is skipped and counted. Execution happens in its own goroutine so the
// ticker loop is never blocked by a slow probe.
func (s *Scheduler) tick(ctx context.Context, j *job) {
	if !j.running.CompareAndSwap(false, true) {
		j.skipped.Add(1)
		return
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer j.running.Store(false)
		// A Prober must never panic, but a buggy one should not take down the
		// whole scheduler; recover, log, and let the next tick try again.
		defer func() {
			if r := recover(); r != nil {
				s.logger.Error("probe panicked",
					slog.String("target", j.spec.Name),
					slog.Any("panic", r),
				)
			}
		}()
		s.execute(ctx, j)
	}()
}

// execute acquires a semaphore slot, runs the probe, and stores the result. It
// bails out without running (or storing) if ctx is cancelled, so a shutdown does
// not record a misleading failure for an aborted probe.
//
// The semaphore wait is bounded only by ctx: under sustained saturation a target
// waits for a free slot rather than dropping the run. This is intentional — the
// target stays marked running while it waits, so its subsequent ticks skip
// (skip-if-running), and the run still happens once a slot frees, favouring
// eventual coverage over discarding the measurement.
func (s *Scheduler) execute(ctx context.Context, j *job) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-s.sem }()

	result := j.spec.Prober.Probe(ctx)

	// Discard results produced during shutdown.
	if ctx.Err() != nil {
		return
	}

	// Determine whether the success state changed since the last run. Only one
	// probe per target runs at a time (skip-if-running), so this get-then-set is
	// race-free per target.
	prev, existed := s.store.Get(j.spec.Name)
	changed := !existed || prev.Result.Success != result.Success

	rec := store.Record{
		Target: j.spec.Name,
		Type:   j.spec.Type,
		Labels: j.spec.Labels,
		Result: result,
	}
	s.store.Set(rec)
	if s.observer != nil {
		// Feed observation-based metrics (e.g. latency histograms) at probe time,
		// so every probe is captured — not only the last one seen at scrape time.
		s.observer.Observe(rec)
	}
	s.logResult(j, result, changed)
}

// logResult logs state transitions at info and steady state at debug. A target
// that stays down therefore logs once (on the transition), not on every run —
// the current state lives in the metrics; the log is for diagnosing changes.
func (s *Scheduler) logResult(j *job, result probe.Result, changed bool) {
	logger := s.logger.With(
		slog.String("target", j.spec.Name),
		slog.String("probe_type", j.spec.Type),
		slog.Bool("success", result.Success),
		slog.Int64("duration_ms", result.Duration.Milliseconds()),
	)
	switch {
	case changed && result.Success:
		logger.Info("probe recovered")
	case changed && !result.Success:
		logger.Info("probe failing", slog.String("failure_reason", result.FailureReason.String()))
	case result.Success:
		logger.Debug("probe succeeded")
	default:
		logger.Debug("probe still failing", slog.String("failure_reason", result.FailureReason.String()))
	}
}

// JobStat is a per-target counter snapshot for the metrics layer.
type JobStat struct {
	Name    string
	Type    string
	Labels  map[string]string
	Skipped int64
}

// Stats returns a snapshot of per-target scheduler counters.
func (s *Scheduler) Stats() []JobStat {
	out := make([]JobStat, 0, len(s.jobs))
	for _, j := range s.jobs {
		out = append(out, JobStat{
			Name:    j.spec.Name,
			Type:    j.spec.Type,
			Labels:  j.spec.Labels,
			Skipped: j.skipped.Load(),
		})
	}
	return out
}

// initialDelay is the jittered delay before a target's first probe, capped at
// maxInitialDelay so a long-interval target is still probed promptly at startup.
func initialDelay(name string, interval time.Duration) time.Duration {
	d := jitter(name, interval)
	if d > maxInitialDelay {
		return maxInitialDelay
	}
	return d
}

// jitter returns a deterministic per-target offset in [0, interval). Deriving it
// from the target name (not a random source) keeps scheduling reproducible and
// testable while still spreading targets across the interval.
func jitter(name string, interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return time.Duration(h.Sum64() % uint64(interval))
}
