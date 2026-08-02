package scheduler

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/clock"
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
}

func (f *fakeProber) Type() string { return "http" }

func (f *fakeProber) Probe(ctx context.Context) probe.Result {
	f.calls.Add(1)
	if f.tracker != nil {
		f.tracker.enter()
		defer f.tracker.leave()
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
	<-done

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
