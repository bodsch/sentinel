package tcp

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

func baseOpts(addr string) Options {
	return Options{Name: "t", Address: addr, Timeout: 3 * time.Second}
}

func runProbe(t *testing.T, opts Options) probe.Result {
	t.Helper()
	p, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p.Probe(context.Background())
}

// startTCP starts a TCP server on 127.0.0.1 that writes banner (if non-empty) on
// each accepted connection and then closes it. It returns the listen address.
func startTCP(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if banner != "" {
				_, _ = c.Write([]byte(banner))
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

func TestTCPConnectSuccess(t *testing.T) {
	t.Parallel()
	res := runProbe(t, baseOpts(startTCP(t, "")))
	if !res.Success {
		t.Fatalf("expected success, got %s", res.FailureReason)
	}
	if res.Timings.Connect <= 0 {
		t.Errorf("connect duration = %v, want > 0", res.Timings.Connect)
	}
}

func TestTCPConnectionRefused(t *testing.T) {
	t.Parallel()
	// Bind then close to obtain a definitely-closed local port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	res := runProbe(t, baseOpts(addr))
	if res.Success {
		t.Fatal("expected failure connecting to a closed port")
	}
	if res.FailureReason != probe.ReasonConnectionRefused {
		t.Errorf("reason = %q, want connection_refused", res.FailureReason)
	}
}

func TestTCPBannerMatch(t *testing.T) {
	t.Parallel()
	opts := baseOpts(startTCP(t, "SSH-2.0-OpenSSH_9.0\r\n"))
	opts.BannerRegex = []string{"^SSH-2.0"}
	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("expected banner match, got %s", res.FailureReason)
	}
	diag, ok := res.Diagnostics.(*Diagnostics)
	if !ok || diag.Banner == "" {
		t.Errorf("banner not captured: %+v", res.Diagnostics)
	}
}

func TestTCPBannerMismatch(t *testing.T) {
	t.Parallel()
	opts := baseOpts(startTCP(t, "220 smtp ready\r\n"))
	opts.BannerRegex = []string{"^SSH-2.0"}
	res := runProbe(t, opts)
	if res.Success {
		t.Fatal("expected a mismatch failure")
	}
	if res.FailureReason != probe.ReasonValidationFailed {
		t.Errorf("reason = %q, want validation_failed", res.FailureReason)
	}
}

func TestTCPBannerExpectedButNone(t *testing.T) {
	t.Parallel()
	// Server accepts and closes immediately without a banner: nothing is
	// received, so this is a connection-level failure, not a banner mismatch.
	opts := baseOpts(startTCP(t, ""))
	opts.BannerRegex = []string{"^SSH"}
	res := runProbe(t, opts)
	if res.Success {
		t.Fatal("expected failure when no banner arrives")
	}
	if res.FailureReason != probe.ReasonNetworkError {
		t.Errorf("reason = %q, want network_error (connection dropped before banner)", res.FailureReason)
	}
}

// TestTCPBannerFragmented verifies a banner split across TCP segments is
// accumulated and matched (a single read would false-mismatch on the first
// fragment).
func TestTCPBannerFragmented(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("220-mail.example ready\r\n"))
			time.Sleep(20 * time.Millisecond)
			_, _ = c.Write([]byte("220 ESMTP\r\n"))
			_ = c.Close()
		}
	}()

	opts := baseOpts(ln.Addr().String())
	opts.BannerRegex = []string{"ESMTP"}
	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("expected fragmented banner to match, got %s", res.FailureReason)
	}
}

// TestTCPAddressTrimmed verifies a whitespace-padded address still connects
// (validation trims it, so the prober must too).
func TestTCPAddressTrimmed(t *testing.T) {
	t.Parallel()
	addr := startTCP(t, "")
	res := runProbe(t, baseOpts("  "+addr+"  "))
	if !res.Success {
		t.Fatalf("whitespace-padded address should connect, got %s", res.FailureReason)
	}
}

// startEndlessTCP starts a TCP server that writes chunk repeatedly, as fast as
// the peer will take it, and never closes the connection. It reports how many
// bytes it managed to write, so a test can assert the probe stopped reading.
//
// This is a real socket rather than a stubbed net.Conn: the byte cap has to hold
// against a peer that genuinely keeps the stream open, which is exactly what a
// mocked reader cannot demonstrate.
func startEndlessTCP(t *testing.T, chunk []byte) (addr string, written func() int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var sent atomic.Int64
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				for {
					select {
					case <-done:
						return
					default:
					}
					n, werr := c.Write(chunk)
					sent.Add(int64(n))
					if werr != nil {
						return
					}
					// Stop the server itself from running away if the probe ever
					// fails to stop reading; the assertion below catches it.
					if sent.Load() > 64*1024*1024 {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), sent.Load
}

// TestTCPBannerCapStopsAnEndlessStream is the denial-of-service safeguard
// maxBannerBytes documents. Without the cap, a TCP target that streams instead
// of greeting — a misconfigured log shipper, a service that answers with a
// firehose, or a deliberately hostile endpoint — would be appended into a []byte
// until the probe timeout, and Sentinel would allocate up to a timeout's worth
// of that stream *per configured target, per interval*. On a fleet where several
// targets point at the same broken service, that is an OOM in the monitoring
// process: the one component that must survive the outage it is reporting.
//
// The probe must give up at the cap and report a validation failure (the banner
// genuinely never matched), not a timeout and not an unbounded read.
func TestTCPBannerCapStopsAnEndlessStream(t *testing.T) {
	t.Parallel()

	// A chunk that can never satisfy the pattern, so the loop only ends at the
	// cap or the deadline.
	addr, written := startEndlessTCP(t, bytes.Repeat([]byte("x"), 1024))

	opts := baseOpts(addr)
	opts.BannerRegex = []string{`^220 `}
	opts.Timeout = 5 * time.Second

	start := time.Now()
	res := runProbe(t, opts)
	elapsed := time.Since(start)

	if res.Success {
		t.Fatalf("probe succeeded against a stream that never matched %q", opts.BannerRegex[0])
	}
	if res.FailureReason != probe.ReasonValidationFailed {
		t.Errorf("reason = %q, want %q (the cap was reached without a match, which is a "+
			"validation failure, not a connection problem)", res.FailureReason, probe.ReasonValidationFailed)
	}

	// memoryBudget is deliberately NOT derived from maxBannerBytes: asserting
	// against the constant under test would make this pass no matter how large
	// the cap grew. A banner is a protocol greeting, so 64 KiB per in-flight
	// probe is the outer bound worth defending, independent of the current cap.
	const memoryBudget = 64 * 1024

	if maxBannerBytes > memoryBudget {
		t.Fatalf("maxBannerBytes = %d exceeds the %d-byte per-probe memory budget; raising the "+
			"cap this far scales with the target count and reintroduces the exhaustion risk",
			maxBannerBytes, memoryBudget)
	}

	diag, ok := res.Diagnostics.(*Diagnostics)
	if !ok {
		t.Fatalf("diagnostics type = %T, want *Diagnostics", res.Diagnostics)
	}
	if got := len(diag.Banner); got > memoryBudget {
		t.Errorf("retained banner = %d bytes, want at most %d: the read is unbounded and a "+
			"streaming target can exhaust Sentinel's memory", got, memoryBudget)
	}

	// The read must end on its own, well before the deadline. Bounding this by
	// the timeout would let an unbounded read pass as long as the probe
	// eventually times out — which is the bug, not the fix.
	if elapsed > 2*time.Second {
		t.Errorf("probe took %v against a 5s timeout: the read ran to the deadline instead of "+
			"stopping at the byte cap", elapsed)
	}

	// Sanity check on the fixture: the server must have offered materially more
	// than the probe kept, otherwise the stream ran dry on its own and this test
	// would pass even with no cap at all. (The server cannot get much past the
	// cap before the probe closes the connection, so this is compared against
	// what was retained — not against the budget.)
	if offered, kept := written(), int64(len(diag.Banner)); offered <= kept*2 {
		t.Fatalf("the fixture offered %d bytes and the probe kept %d; the stream was not endless "+
			"enough to demonstrate the read is bounded", offered, kept)
	}
}

// TestTCPBannerCapMatchesLate is the counterpart: a banner that only satisfies
// the pattern near the very end of the allowed window must still match. Getting
// the loop bound wrong by one buffer would turn a slow, chatty-but-valid
// greeting (a multiline SMTP banner behind a verbose proxy) into a permanent
// false alarm that pages someone about a healthy mail server.
func TestTCPBannerCapMatchesLate(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = c.Close() }()
		// Fill almost the whole window with noise, one segment at a time, then
		// send the token that satisfies the pattern.
		if _, werr := c.Write(bytes.Repeat([]byte("noise\r\n"), (maxBannerBytes-64)/7)); werr != nil {
			return
		}
		_, _ = c.Write([]byte("READY\r\n"))
	}()

	opts := baseOpts(ln.Addr().String())
	opts.BannerRegex = []string{`READY`}
	res := runProbe(t, opts)

	if !res.Success {
		t.Fatalf("a banner that matches just below the %d-byte cap was rejected: %s",
			maxBannerBytes, res.FailureReason)
	}
}
