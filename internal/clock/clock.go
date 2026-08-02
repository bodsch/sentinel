// Package clock abstracts time so scheduler and probe logic can be tested
// deterministically. Production code uses Real; tests use a Fake whose time only
// advances when the test tells it to.
//
// No Sentinel code outside this package should call time.Now, time.NewTicker or
// time.After directly — always go through a Clock.
package clock

import "time"

// Clock is the minimal set of time operations Sentinel depends on.
type Clock interface {
	// Now returns the current time.
	Now() time.Time

	// NewTicker returns a ticker that delivers ticks every d. The caller must
	// call Stop to release it.
	NewTicker(d time.Duration) Ticker

	// After returns a channel that receives once, after d has elapsed.
	After(d time.Duration) <-chan time.Time
}

// Ticker abstracts *time.Ticker so a Fake clock can drive ticks explicitly.
type Ticker interface {
	// C is the channel on which ticks are delivered.
	C() <-chan time.Time
	// Stop halts the ticker; no further ticks are delivered.
	Stop()
}

// Real is a Clock backed by the standard time package. The zero value is ready
// to use.
type Real struct{}

// Now implements Clock.
func (Real) Now() time.Time { return time.Now() }

// After implements Clock.
func (Real) After(d time.Duration) <-chan time.Time { return time.After(d) }

// NewTicker implements Clock.
func (Real) NewTicker(d time.Duration) Ticker { return &realTicker{t: time.NewTicker(d)} }

// realTicker adapts *time.Ticker to the Ticker interface.
type realTicker struct{ t *time.Ticker }

func (r *realTicker) C() <-chan time.Time { return r.t.C }
func (r *realTicker) Stop()               { r.t.Stop() }

// Ensure Real satisfies Clock at compile time.
var _ Clock = Real{}
