package http

import (
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// TestStalledPhase pins the attribution order on hand-built traces: the first
// phase started but not finished wins, and between phases the next one is
// reported.
func TestStalledPhase(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cases := []struct {
		name string
		tr   *hopTrace
		want probe.Phase
	}{
		{"nothing recorded", &hopTrace{}, probe.PhaseNone},
		{"resolving", &hopTrace{dnsStart: now}, probe.PhaseDNS},
		{"resolved, connect not started", &hopTrace{dnsStart: now, dnsDone: now}, probe.PhaseConnect},
		{"connecting", &hopTrace{dnsStart: now, dnsDone: now, connectStart: now}, probe.PhaseConnect},
		{"connecting to an IP literal", &hopTrace{connectStart: now}, probe.PhaseConnect},
		{"plain http waiting", &hopTrace{connectStart: now, connectDone: now}, probe.PhaseTTFB},
		{"handshaking", &hopTrace{connectStart: now, connectDone: now, tlsStart: now}, probe.PhaseTLS},
		{"https waiting", &hopTrace{connectStart: now, connectDone: now, tlsStart: now, tlsDone: now}, probe.PhaseTTFB},
		{"reading body", &hopTrace{connectStart: now, connectDone: now, firstByte: now}, probe.PhaseDownload},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.tr.stalledPhase(); got != tc.want {
				t.Errorf("stalledPhase() = %q, want %q", got, tc.want)
			}
		})
	}
}

// timeoutPhase runs a 200 ms probe against url and returns the result after
// asserting it timed out.
func timeoutPhase(t *testing.T, url string) probe.Result {
	t.Helper()
	opts := baseOpts(url)
	opts.Timeout = 200 * time.Millisecond
	opts.TLSSkipVerify = true
	res := runProbe(t, opts)
	if !res.FailureReason.IsTimeout() {
		t.Fatalf("reason = %q, want a timeout", res.FailureReason)
	}
	return res
}

func TestTimeoutPhaseTTFB(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(_ nethttp.ResponseWriter, r *nethttp.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	if got := timeoutPhase(t, srv.URL).TimeoutPhase; got != probe.PhaseTTFB {
		t.Errorf("phase = %q, want ttfb", got)
	}
}

func TestTimeoutPhaseDownload(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("partial"))
		w.(nethttp.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()

	if got := timeoutPhase(t, srv.URL).TimeoutPhase; got != probe.PhaseDownload {
		t.Errorf("phase = %q, want download", got)
	}
}

// TestTimeoutPhaseTLS points an https URL at a listener that accepts and stays
// silent, so the handshake never completes.
func TestTimeoutPhaseTLS(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() { <-done; _ = conn.Close() }()
		}
	}()

	if got := timeoutPhase(t, "https://"+ln.Addr().String()+"/").TimeoutPhase; got != probe.PhaseTLS {
		t.Errorf("phase = %q, want tls", got)
	}
}

// TestNoPhaseOnNonTimeoutFailure keeps the field meaningful: a failure that
// already says where it happened carries no phase.
func TestNoPhaseOnNonTimeoutFailure(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	res := runProbe(t, baseOpts(srv.URL))
	if res.FailureReason != probe.ReasonHTTPStatusError {
		t.Fatalf("reason = %q, want http_status_error", res.FailureReason)
	}
	if res.TimeoutPhase != probe.PhaseNone {
		t.Errorf("phase = %q, want none", res.TimeoutPhase)
	}
}
