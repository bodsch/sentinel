package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/clock"
	"bodsch.me/sentinel/internal/logging"
	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

// concTracker records the peak number of concurrent probes.
type concTracker struct {
	active atomic.Int64
	max    atomic.Int64
}

func (c *concTracker) enter() {
	a := c.active.Add(1)
	for {
		m := c.max.Load()
		if a <= m || c.max.CompareAndSwap(m, a) {
			break
		}
	}
}

func (c *concTracker) leave() { c.active.Add(-1) }

// fakeProber is a controllable probe.Prober for tests.
type fakeProber struct {
	calls   atomic.Int64
	block   chan struct{} // if non-nil, Probe blocks until closed or ctx done
	result  probe.Result
	tracker *concTracker
	onProbe func() // if non-nil, called inside Probe (e.g. to cancel the context)
}

func (f *fakeProber) Type() string { return "http" }

func (f *fakeProber) Probe(ctx context.Context) probe.Result {
	f.calls.Add(1)
	if f.tracker != nil {
		f.tracker.enter()
		defer f.tracker.leave()
	}
	if f.onProbe != nil {
		f.onProbe()
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
		}
	}
	return f.result
}

var _ probe.Prober = (*fakeProber)(nil)

// add registers a job and fails the test if the spec is rejected.
func add(t *testing.T, s *Scheduler, spec JobSpec) {
	t.Helper()
	if err := s.Add(spec); err != nil {
		t.Fatalf("Add(%q): %v", spec.Name, err)
	}
}

func eventually(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}

func TestJitterDeterministicAndBounded(t *testing.T) {
	t.Parallel()

	interval := time.Minute
	a1 := jitter("target-a", interval)
	a2 := jitter("target-a", interval)
	b := jitter("target-b", interval)

	if a1 != a2 {
		t.Errorf("jitter not deterministic: %v vs %v", a1, a2)
	}
	if a1 < 0 || a1 >= interval {
		t.Errorf("jitter %v out of range [0, %v)", a1, interval)
	}
	if a1 == b {
		t.Error("expected different targets to get different jitter (hash collision unlikely)")
	}
	if got := jitter("x", 0); got != 0 {
		t.Errorf("jitter with zero interval = %v, want 0", got)
	}
}

func TestTickSkipsWhenRunning(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	p := &fakeProber{block: release, tracker: &concTracker{}}
	s := New(Options{Store: store.New(), Concurrency: 10})
	add(t, s, JobSpec{Name: "x", Type: "http", Interval: time.Minute, Prober: p})
	j := s.jobs[0]
	ctx := context.Background()

	s.tick(ctx, j) // first run: sets running, prober blocks
	eventually(t, func() bool { return p.calls.Load() == 1 }, time.Second)

	s.tick(ctx, j) // overlapping tick: must be skipped, not queued
	if got := j.skipped.Load(); got != 1 {
		t.Fatalf("skipped = %d, want 1", got)
	}

	close(release)
	s.wg.Wait()
	if got := p.calls.Load(); got != 1 {
		t.Fatalf("prober called %d times, want 1 (the overlap was skipped)", got)
	}
}

func TestExecuteStoresResult(t *testing.T) {
	t.Parallel()

	st := store.New()
	p := &fakeProber{tracker: &concTracker{}, result: probe.Result{Success: true}}
	s := New(Options{Store: st, Concurrency: 10})
	j := &job{spec: JobSpec{Name: "x", Type: "http", Prober: p}}

	s.execute(context.Background(), j)

	rec, ok := st.Get("x")
	if !ok {
		t.Fatal("expected a stored result")
	}
	if !rec.Result.Success {
		t.Error("stored result should be a success")
	}
}

func TestExecuteDiscardsOnCancel(t *testing.T) {
	t.Parallel()

	st := store.New()
	p := &fakeProber{tracker: &concTracker{}, result: probe.Result{Success: true}}
	s := New(Options{Store: st, Concurrency: 10})
	j := &job{spec: JobSpec{Name: "x", Type: "http", Prober: p}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.execute(ctx, j)

	if st.Len() != 0 {
		t.Fatalf("expected no stored result on a cancelled context, got %d", st.Len())
	}
}

// recordingObserver captures observed records for assertions.
type recordingObserver struct {
	mu   sync.Mutex
	recs []store.Record
}

func (o *recordingObserver) Observe(r store.Record) {
	o.mu.Lock()
	o.recs = append(o.recs, r)
	o.mu.Unlock()
}

func (o *recordingObserver) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.recs)
}

func TestExecuteNotifiesObserver(t *testing.T) {
	t.Parallel()

	st := store.New()
	obs := &recordingObserver{}
	p := &fakeProber{tracker: &concTracker{}, result: probe.Result{Success: true, Duration: 42 * time.Millisecond}}
	s := New(Options{Store: st, Observer: obs, Concurrency: 10})
	j := &job{spec: JobSpec{Name: "x", Type: "http", Prober: p}}

	s.execute(context.Background(), j)

	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.recs) != 1 {
		t.Fatalf("observer calls = %d, want 1", len(obs.recs))
	}
	if got := obs.recs[0]; got.Target != "x" || got.Result.Duration != 42*time.Millisecond {
		t.Errorf("observed record = %+v, want target x / 42ms", got)
	}
}

func TestExecuteDoesNotNotifyObserverOnCancel(t *testing.T) {
	t.Parallel()

	st := store.New()
	obs := &recordingObserver{}
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel *during* Probe: the semaphore is acquired first (ctx still live at
	// the top select), then the probe cancels, so execute() deterministically
	// reaches the post-probe discard guard. Cancelling before execute would race
	// the sem-acquire-vs-ctx.Done select and only reach the guard ~half the time.
	p := &fakeProber{tracker: &concTracker{}, result: probe.Result{Success: true}, onProbe: cancel}
	s := New(Options{Store: st, Observer: obs, Concurrency: 10})
	j := &job{spec: JobSpec{Name: "x", Type: "http", Prober: p}}

	s.execute(ctx, j)

	if st.Len() != 0 {
		t.Errorf("stored %d results on a shutdown-cancelled probe, want 0", st.Len())
	}
	if n := obs.count(); n != 0 {
		t.Errorf("observer called %d times on a shutdown-cancelled probe, want 0", n)
	}
}

func TestConcurrencyBounded(t *testing.T) {
	t.Parallel()

	const limit = 2
	const jobs = 6

	tracker := &concTracker{}
	release := make(chan struct{})
	s := New(Options{Store: store.New(), Concurrency: limit})
	for i := 0; i < jobs; i++ {
		p := &fakeProber{block: release, tracker: tracker}
		add(t, s, JobSpec{Name: fmt.Sprintf("t%d", i), Type: "http", Interval: time.Minute, Prober: p})
	}

	ctx := context.Background()
	for _, j := range s.jobs {
		s.tick(ctx, j)
	}

	// Wait until the semaphore is saturated, then release.
	eventually(t, func() bool { return tracker.active.Load() == limit }, 2*time.Second)
	close(release)
	s.wg.Wait()

	if got := tracker.max.Load(); got != limit {
		t.Fatalf("peak concurrency = %d, want %d", got, limit)
	}
}

func TestRunProbesAndShutsDown(t *testing.T) {
	t.Parallel()

	fake := clock.NewFake(time.Unix(0, 0))
	st := store.New()
	p := &fakeProber{tracker: &concTracker{}, result: probe.Result{Success: true}}
	s := New(Options{Clock: fake, Store: st, Concurrency: 10})
	add(t, s, JobSpec{Name: "x", Type: "http", Interval: time.Minute, Prober: p})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()

	// Advance repeatedly until the initial (jittered) probe fires. Advancing more
	// than once is harmless; the timer fires once registered.
	eventually(t, func() bool {
		fake.Advance(time.Minute)
		return p.calls.Load() >= 1
	}, 2*time.Second)

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	if _, ok := st.Get("x"); !ok {
		t.Fatal("expected a stored result after a probe ran")
	}
}

func TestAddRejectsInvalidSpecs(t *testing.T) {
	t.Parallel()

	s := New(Options{Store: store.New()})
	good := &fakeProber{}

	if err := s.Add(JobSpec{Name: "", Interval: time.Minute, Prober: good}); err == nil {
		t.Error("expected error for empty name")
	}
	if err := s.Add(JobSpec{Name: "x", Interval: 0, Prober: good}); err == nil {
		t.Error("expected error for zero interval")
	}
	if err := s.Add(JobSpec{Name: "x", Interval: -time.Second, Prober: good}); err == nil {
		t.Error("expected error for negative interval")
	}
	if err := s.Add(JobSpec{Name: "x", Interval: time.Minute, Prober: nil}); err == nil {
		t.Error("expected error for nil prober")
	}
	if len(s.jobs) != 0 {
		t.Errorf("no invalid job should have been registered, got %d", len(s.jobs))
	}
}

// TestExecuteDiscardsWhenCancelledDuringProbe exercises the real discard window:
// the probe is in flight when the context is cancelled.
func TestExecuteDiscardsWhenCancelledDuringProbe(t *testing.T) {
	t.Parallel()

	st := store.New()
	// The prober blocks until ctx is done, then returns — simulating a probe
	// still running when shutdown begins.
	p := &fakeProber{block: make(chan struct{}), tracker: &concTracker{}, result: probe.Result{Success: true}}
	s := New(Options{Store: st, Concurrency: 10})
	j := &job{spec: JobSpec{Name: "x", Type: "http", Prober: p}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.execute(ctx, j)
		close(done)
	}()

	eventually(t, func() bool { return p.calls.Load() == 1 }, time.Second) // probe in flight
	cancel()                                                               // cancel mid-probe
	// Deadline, not a bare receive: if execute() stopped honouring the cancel it
	// would block here and hang the whole package's test run instead of naming
	// the regression.
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("execute did not return after the context was cancelled mid-probe; " +
			"a shutdown would block on the scheduler drain until the 10s timeout fires")
	}

	if st.Len() != 0 {
		t.Fatalf("expected the in-flight result to be discarded, got %d stored", st.Len())
	}
}

type panicProber struct{}

func (panicProber) Type() string                       { return "http" }
func (panicProber) Probe(context.Context) probe.Result { panic("boom") }

// TestProbePanicDoesNotCrash verifies a panicking prober is contained: the
// scheduler recovers, the running flag is reset, and no goroutine escapes.
func TestProbePanicDoesNotCrash(t *testing.T) {
	t.Parallel()

	s := New(Options{Store: store.New(), Concurrency: 10})
	j := &job{spec: JobSpec{Name: "x", Type: "http", Interval: time.Minute, Prober: panicProber{}}}

	s.tick(context.Background(), j)
	s.wg.Wait() // must not crash the test binary

	if j.running.Load() {
		t.Error("running flag was not reset after a panicking probe")
	}
}

// logLines decodes the JSON log records written to buf.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// newLoggingScheduler returns a scheduler logging JSON at debug into buf.
func newLoggingScheduler(t *testing.T, st *store.Store) (*Scheduler, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	s := New(Options{
		Store:       st,
		Concurrency: 10,
		Logger:      logging.New(&buf, logging.Options{Level: slog.LevelDebug, Format: logging.FormatJSON}),
	})
	return s, &buf
}

// TestLogResultCarriesTheCoreFieldSet verifies the field schema the logging
// package documents actually reaches a probe line. These fields are how an
// operator finds one target's history in a fleet-wide stream and how a log-based
// alert filters failures; a probe line missing "target" is unattributable, and a
// second spelling of "duration_ms" splits every dashboard built on it in half.
func TestLogResultCarriesTheCoreFieldSet(t *testing.T) {
	t.Parallel()

	st := store.New()
	s, buf := newLoggingScheduler(t, st)
	j := &job{spec: JobSpec{Name: "api-prod", Type: "http", Prober: &fakeProber{
		result: probe.Result{Success: false, FailureReason: probe.ReasonTimeout, Duration: 1500 * time.Millisecond},
	}}}

	s.execute(context.Background(), j)

	recs := logLines(t, buf)
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want 1: %q", len(recs), buf.String())
	}
	rec := recs[0]
	if rec[logging.FieldTarget] != "api-prod" {
		t.Errorf("%s = %v, want \"api-prod\"", logging.FieldTarget, rec[logging.FieldTarget])
	}
	if rec[logging.FieldProbeType] != "http" {
		t.Errorf("%s = %v, want \"http\"", logging.FieldProbeType, rec[logging.FieldProbeType])
	}
	if rec[logging.FieldSuccess] != false {
		t.Errorf("%s = %v, want false", logging.FieldSuccess, rec[logging.FieldSuccess])
	}
	if got, ok := rec[logging.FieldDurationMs].(float64); !ok || got != 1500 {
		t.Errorf("%s = %v (%T), want 1500", logging.FieldDurationMs, rec[logging.FieldDurationMs], rec[logging.FieldDurationMs])
	}
	if rec[logging.FieldFailureReason] != probe.ReasonTimeout.String() {
		t.Errorf("%s = %v, want %q", logging.FieldFailureReason, rec[logging.FieldFailureReason], probe.ReasonTimeout)
	}
}

// TestLogResultOmitsFailureReasonOnSuccess is the other half of the schema
// decision: failure_reason lives at the call site precisely so a success line
// does not carry it. A success line stamped with failure_reason="none" would
// make `failure_reason!=""` — the obvious way to select failures in a log query
// — match every single probe line, and a log-based alert built on it would fire
// permanently.
func TestLogResultOmitsFailureReasonOnSuccess(t *testing.T) {
	t.Parallel()

	st := store.New()
	s, buf := newLoggingScheduler(t, st)
	j := &job{spec: JobSpec{Name: "api-prod", Type: "http", Prober: &fakeProber{
		result: probe.Result{Success: true, Duration: 20 * time.Millisecond},
	}}}

	s.execute(context.Background(), j)

	recs := logLines(t, buf)
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want 1: %q", len(recs), buf.String())
	}
	if _, present := recs[0][logging.FieldFailureReason]; present {
		t.Errorf("a successful probe line carries %s = %v, want the field absent",
			logging.FieldFailureReason, recs[0][logging.FieldFailureReason])
	}
}

// TestSteadyStateLogsOnlyTheTransition is the promise in logResult's own doc
// comment: a target that stays down logs once, on the transition, not on every
// run. It is a load promise, not a cosmetic one — a 1000-target fleet in a
// regional outage probing every 15s would otherwise emit 4000 info lines a
// minute, saturating the log pipeline at exactly the moment the transition lines
// are the only thing worth reading, and the recovery line would be buried in
// them.
func TestSteadyStateLogsOnlyTheTransition(t *testing.T) {
	t.Parallel()

	st := store.New()
	s, buf := newLoggingScheduler(t, st)
	p := &fakeProber{result: probe.Result{Success: false, FailureReason: probe.ReasonTimeout}}
	j := &job{spec: JobSpec{Name: "api-prod", Type: "http", Prober: p}}

	// Four consecutive failing runs, then two successful ones.
	for i := 0; i < 4; i++ {
		s.execute(context.Background(), j)
	}
	p.result = probe.Result{Success: true}
	for i := 0; i < 2; i++ {
		s.execute(context.Background(), j)
	}

	var infoMsgs []string
	for _, rec := range logLines(t, buf) {
		if rec["level"] == "INFO" {
			infoMsgs = append(infoMsgs, rec["msg"].(string))
		}
	}

	want := []string{"probe failing", "probe recovered"}
	if len(infoMsgs) != len(want) {
		t.Fatalf("got %d info lines %v across 4 failures + 2 successes, want exactly %v "+
			"(one per state transition)", len(infoMsgs), infoMsgs, want)
	}
	for i := range want {
		if infoMsgs[i] != want[i] {
			t.Errorf("info line %d = %q, want %q", i, infoMsgs[i], want[i])
		}
	}
}

// TestFirstRunOfAFailingTargetLogsAtInfo pins the cold-start case. On startup no
// record exists yet, so the first result is a transition by definition. If a
// target that was already broken when Sentinel started logged its failure only
// at debug, a restart during an outage would produce no info-level evidence that
// the target was down — the very thing an operator greps for after a restart.
func TestFirstRunOfAFailingTargetLogsAtInfo(t *testing.T) {
	t.Parallel()

	st := store.New()
	s, buf := newLoggingScheduler(t, st)
	j := &job{spec: JobSpec{Name: "api-prod", Type: "http", Prober: &fakeProber{
		result: probe.Result{Success: false, FailureReason: probe.ReasonConnectionRefused},
	}}}

	s.execute(context.Background(), j)

	recs := logLines(t, buf)
	if len(recs) != 1 {
		t.Fatalf("got %d log records, want 1: %q", len(recs), buf.String())
	}
	if recs[0]["level"] != "INFO" || recs[0]["msg"] != "probe failing" {
		t.Errorf("first-ever result of a failing target logged as %v %q, want INFO \"probe failing\"",
			recs[0]["level"], recs[0]["msg"])
	}
}
