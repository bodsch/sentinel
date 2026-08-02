package tcp

import (
	"context"
	"net"
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
