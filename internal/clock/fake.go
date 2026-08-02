package clock

import (
	"sync"
	"time"
)

// Fake is a deterministic Clock for tests. Time only advances when Advance is
// called. Tickers and After timers created against it fire when Advance moves
// virtual time past their next deadline.
//
// Fake is safe for concurrent use.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	tickers []*fakeTicker
	timers  []*fakeTimer
}

// NewFake returns a Fake clock started at the given time.
func NewFake(start time.Time) *Fake {
	return &Fake{now: start}
}

// Now implements Clock.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance moves virtual time forward by d, firing any tickers and timers whose
// deadline is reached. Ticks/fires are delivered on buffered channels so a
// caller that is not yet receiving does not deadlock Advance.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	now := f.now

	for _, t := range f.tickers {
		if t.stopped {
			continue
		}
		for !t.next.After(now) {
			select {
			case t.ch <- t.next:
			default:
			}
			t.next = t.next.Add(t.interval)
		}
	}

	remaining := f.timers[:0]
	var fired []*fakeTimer
	for _, t := range f.timers {
		if !t.deadline.After(now) {
			fired = append(fired, t)
		} else {
			remaining = append(remaining, t)
		}
	}
	f.timers = remaining
	f.mu.Unlock()

	for _, t := range fired {
		select {
		case t.ch <- now:
		default:
		}
	}
}

// NewTicker implements Clock.
func (f *Fake) NewTicker(d time.Duration) Ticker {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTicker{
		f:        f,
		ch:       make(chan time.Time, 1),
		interval: d,
		next:     f.now.Add(d),
	}
	f.tickers = append(f.tickers, t)
	return t
}

// After implements Clock.
func (f *Fake) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTimer{
		ch:       make(chan time.Time, 1),
		deadline: f.now.Add(d),
	}
	f.timers = append(f.timers, t)
	return t.ch
}

type fakeTicker struct {
	f        *Fake
	ch       chan time.Time
	interval time.Duration
	next     time.Time
	stopped  bool // guarded by f.mu
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }

// Stop marks the ticker stopped under the parent clock's lock, so Advance (which
// holds the same lock) observes it consistently.
func (t *fakeTicker) Stop() {
	t.f.mu.Lock()
	t.stopped = true
	t.f.mu.Unlock()
}

type fakeTimer struct {
	ch       chan time.Time
	deadline time.Time
}

// Ensure Fake satisfies Clock at compile time.
var _ Clock = (*Fake)(nil)
