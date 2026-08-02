package http

import (
	"crypto/tls"
	"net/http/httptrace"
	"sync"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// hopTrace records phase timestamps for a single HTTP request (one redirect
// hop) via net/http/httptrace. Because connections are never reused
// (keep-alives are disabled), every hop performs a full DNS/TCP/TLS sequence, so
// each phase fires and can be measured.
//
// Access is guarded by a mutex: under dual-stack "Happy Eyeballs" dialing the
// ConnectStart/ConnectDone callbacks fire from several dial goroutines
// concurrently, and the losing goroutine may still fire a callback after
// RoundTrip returns and timings() reads the fields.
type hopTrace struct {
	mu           sync.Mutex
	dnsStart     time.Time
	dnsDone      time.Time
	connectStart time.Time
	connectDone  time.Time
	tlsStart     time.Time
	tlsDone      time.Time
	firstByte    time.Time
}

// newHopTrace returns an empty hopTrace.
func newHopTrace() *hopTrace {
	return &hopTrace{}
}

// clientTrace returns the httptrace.ClientTrace that records this hop's events.
// Every callback takes the mutex, so concurrent dial callbacks are safe. For
// the connect phase the first observed start/done is kept, so a late callback
// from a losing dial goroutine does not overwrite the winning connection's
// timing.
func (t *hopTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { t.setIfZero(&t.dnsStart) },
		DNSDone:              func(httptrace.DNSDoneInfo) { t.set(&t.dnsDone) },
		ConnectStart:         func(_, _ string) { t.setIfZero(&t.connectStart) },
		ConnectDone:          func(_, _ string, _ error) { t.setIfZero(&t.connectDone) },
		TLSHandshakeStart:    func() { t.set(&t.tlsStart) },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { t.set(&t.tlsDone) },
		GotFirstResponseByte: func() { t.set(&t.firstByte) },
	}
}

// set records now into the given field under the lock.
func (t *hopTrace) set(field *time.Time) {
	t.mu.Lock()
	*field = time.Now()
	t.mu.Unlock()
}

// setIfZero records now into the given field only if it is still zero.
func (t *hopTrace) setIfZero(field *time.Time) {
	t.mu.Lock()
	if field.IsZero() {
		*field = time.Now()
	}
	t.mu.Unlock()
}

// timings computes the per-phase breakdown. downloadEnd is when body reading
// finished. It takes the lock to read a consistent snapshot even if a losing
// dial goroutine is still firing callbacks. All phases are guarded so a missing
// or out-of-order event yields zero rather than a negative duration.
//
// The waiting phase (TTFB) is measured from when the connection became usable
// (TLS done for HTTPS, TCP connect done for HTTP) to the first response byte, so
// DNS/TCP/TLS/TTFB/Download describe distinct, non-overlapping bands.
func (t *hopTrace) timings(downloadEnd time.Time) probe.Timings {
	t.mu.Lock()
	defer t.mu.Unlock()

	var out probe.Timings
	out.DNS = diff(t.dnsStart, t.dnsDone)
	out.Connect = diff(t.connectStart, t.connectDone)
	out.TLS = diff(t.tlsStart, t.tlsDone)

	ready := t.connectDone
	if !t.tlsDone.IsZero() {
		ready = t.tlsDone
	}
	out.TTFB = diff(ready, t.firstByte)
	out.Download = diff(t.firstByte, downloadEnd)

	return out
}

// diff returns to-from if both are set and to is after from, else 0.
func diff(from, to time.Time) time.Duration {
	if from.IsZero() || to.IsZero() || !to.After(from) {
		return 0
	}
	return to.Sub(from)
}
