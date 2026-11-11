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
	// tlsErr is the error the TLS handshake ended with, nil when it succeeded
	// or did not run.
	tlsErr error
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
		TLSHandshakeDone:     t.handshakeDone,
		GotFirstResponseByte: func() { t.set(&t.firstByte) },
	}
}

// handshakeDone records the end of the TLS handshake and its error.
func (t *hopTrace) handshakeDone(_ tls.ConnectionState, err error) {
	t.mu.Lock()
	t.tlsDone = time.Now()
	t.tlsErr = err
	t.mu.Unlock()
}

// handshakeError returns the error the TLS handshake ended with, or nil when it
// succeeded or did not run. A round trip that failed with a handshake error is
// classified from this error, which is the one crypto/tls returned before
// net/http wrapped it.
func (t *hopTrace) handshakeError() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tlsErr
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

// stalledPhase reports the phase this hop had reached: the first phase that was
// started but not finished, or, between phases, the one about to begin. It is
// read after a timeout to say where the hop was stuck.
//
// The order follows the request's life: the response body (download) once a
// first byte arrived, waiting for that byte (ttfb) once the connection was
// usable, otherwise the TLS handshake, TCP connect or name resolution. A hop with
// no recorded event at all yields PhaseNone — nothing can be attributed.
func (t *hopTrace) stalledPhase() probe.Phase {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch {
	case !t.firstByte.IsZero():
		return probe.PhaseDownload
	case !t.tlsDone.IsZero():
		return probe.PhaseTTFB
	case !t.tlsStart.IsZero():
		return probe.PhaseTLS
	case !t.connectDone.IsZero():
		// Plain HTTP waits for the response here; for HTTPS the handshake is
		// about to start, but no TLS event fired, so the time was spent waiting.
		return probe.PhaseTTFB
	case !t.connectStart.IsZero(), !t.dnsDone.IsZero():
		return probe.PhaseConnect
	case !t.dnsStart.IsZero():
		return probe.PhaseDNS
	default:
		return probe.PhaseNone
	}
}

// diff returns to-from if both are set and to is after from, else 0.
func diff(from, to time.Time) time.Duration {
	if from.IsZero() || to.IsZero() || !to.After(from) {
		return 0
	}
	return to.Sub(from)
}
