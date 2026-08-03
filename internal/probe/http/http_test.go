package http

import (
	"context"
	"crypto/tls"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// baseOpts returns Options for a target with sane defaults for tests.
func baseOpts(url string) Options {
	return Options{
		Name:            "test",
		Method:          "GET",
		URL:             url,
		Timeout:         5 * time.Second,
		FollowRedirects: true,
		MaxRedirects:    10,
		MaxBodyBytes:    1 << 20,
		ExpectStatus:    200,
	}
}

// runProbe builds a Prober and runs it once.
func runProbe(t *testing.T, opts Options) probe.Result {
	t.Helper()
	p, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p.Probe(context.Background())
}

func diag(t *testing.T, res probe.Result) *Diagnostics {
	t.Helper()
	d, ok := res.Diagnostics.(*Diagnostics)
	if !ok {
		t.Fatalf("diagnostics type = %T, want *Diagnostics", res.Diagnostics)
	}
	return d
}

func TestProbeSuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	res := runProbe(t, baseOpts(srv.URL))
	if !res.Success {
		t.Fatalf("expected success, got reason %q", res.FailureReason)
	}
	if res.Duration <= 0 {
		t.Error("duration should be positive")
	}
	if res.Timestamp.IsZero() {
		t.Error("timestamp not set")
	}
	d := diag(t, res)
	if d.StatusCode != 200 {
		t.Errorf("status = %d, want 200", d.StatusCode)
	}
	if d.ProbeType() != ProbeType {
		t.Errorf("ProbeType = %q, want %q", d.ProbeType(), ProbeType)
	}
}

func TestProbeStatusMismatch(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	res := runProbe(t, baseOpts(srv.URL))
	if res.Success {
		t.Fatal("expected failure for status mismatch")
	}
	if res.FailureReason != probe.ReasonHTTPStatusError {
		t.Errorf("reason = %q, want %q", res.FailureReason, probe.ReasonHTTPStatusError)
	}
}

func TestProbeBodyRegex(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer srv.Close()

	pass := baseOpts(srv.URL)
	pass.BodyRegex = []string{"healthy"}
	if res := runProbe(t, pass); !res.Success {
		t.Fatalf("expected success, got %q", res.FailureReason)
	}

	fail := baseOpts(srv.URL)
	fail.BodyRegex = []string{"unhealthy"}
	res := runProbe(t, fail)
	if res.Success || res.FailureReason != probe.ReasonValidationFailed {
		t.Fatalf("expected validation_failed, got success=%v reason=%q", res.Success, res.FailureReason)
	}
}

func TestProbeHeaderMatch(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("X-Service", "frontend")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ok := baseOpts(srv.URL)
	ok.Headers = map[string]string{"X-Service": "frontend"}
	if res := runProbe(t, ok); !res.Success {
		t.Fatalf("expected success, got %q", res.FailureReason)
	}

	bad := baseOpts(srv.URL)
	bad.Headers = map[string]string{"X-Service": "backend"}
	if res := runProbe(t, bad); res.Success {
		t.Fatal("expected header mismatch failure")
	}
}

func TestProbeHEADSendsHead(t *testing.T) {
	t.Parallel()

	var gotMethod string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		gotMethod = r.Method
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.Method = "HEAD"
	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("expected success, got %q", res.FailureReason)
	}
	if gotMethod != "HEAD" {
		t.Errorf("server saw method %q, want HEAD", gotMethod)
	}
}

func TestProbeUserAgent(t *testing.T) {
	t.Parallel()

	var gotUA string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	runProbe(t, baseOpts(srv.URL))
	if !strings.HasPrefix(gotUA, "sentinel/") {
		t.Errorf("User-Agent = %q, want prefix sentinel/", gotUA)
	}
}

func TestProbeMaxBodyBytesTruncates(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = w.Write([]byte("START" + strings.Repeat("x", 5000) + "END"))
	}))
	defer srv.Close()

	// Cap below the "END" marker: a regex for START matches, for END must not.
	opts := baseOpts(srv.URL)
	opts.MaxBodyBytes = 10
	opts.BodyRegex = []string{"START"}
	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("expected START to match within cap, got %q", res.FailureReason)
	}

	opts.BodyRegex = []string{"END"}
	if res := runProbe(t, opts); res.Success {
		t.Fatal("expected END to be truncated away (validation failure)")
	}
}

func TestProbeMaxBodyBytesUncapped(t *testing.T) {
	t.Parallel()

	// A body far larger than the default 1 MiB cap, with an END marker last.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = w.Write([]byte("START" + strings.Repeat("x", 2<<20) + "END"))
	}))
	defer srv.Close()

	// MaxBodyBytes == 0 disables the cap: the full body is read, so a regex for
	// the trailing END marker (beyond the default cap) must match.
	opts := baseOpts(srv.URL)
	opts.MaxBodyBytes = 0
	opts.BodyRegex = []string{"END"}
	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("expected END to be read with the cap disabled, got %q", res.FailureReason)
	}
}

func TestRedirectFollow(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/a":
			nethttp.Redirect(w, r, "/b", nethttp.StatusFound)
		case "/b":
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	res := runProbe(t, baseOpts(srv.URL+"/a"))
	if !res.Success {
		t.Fatalf("expected success after redirect, got %q", res.FailureReason)
	}
	d := diag(t, res)
	if len(d.Redirects) != 1 {
		t.Fatalf("redirect chain len = %d, want 1", len(d.Redirects))
	}
	if !strings.HasSuffix(d.FinalURL, "/b") {
		t.Errorf("final URL = %q, want .../b", d.FinalURL)
	}
}

func TestRedirectLoop(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/a":
			nethttp.Redirect(w, r, "/b", nethttp.StatusFound)
		case "/b":
			nethttp.Redirect(w, r, "/a", nethttp.StatusFound)
		}
	}))
	defer srv.Close()

	res := runProbe(t, baseOpts(srv.URL+"/a"))
	if res.FailureReason != probe.ReasonRedirectLoop {
		t.Fatalf("reason = %q, want redirect_loop", res.FailureReason)
	}
}

func TestRedirectLimit(t *testing.T) {
	t.Parallel()

	// Each hop redirects to a new unique path, so it is never a loop — only the
	// limit stops it.
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, r.URL.Path+"x", nethttp.StatusFound)
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL + "/a")
	opts.MaxRedirects = 3
	res := runProbe(t, opts)
	if res.FailureReason != probe.ReasonRedirectLimit {
		t.Fatalf("reason = %q, want redirect_limit_exceeded", res.FailureReason)
	}
	d := diag(t, res)
	if len(d.Redirects) != 3 {
		t.Errorf("followed %d redirects, want 3 before limit", len(d.Redirects))
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, "/other", nethttp.StatusFound)
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.FollowRedirects = false
	// Expect the 302 as the final response; expecting 200 makes it a status error.
	res := runProbe(t, opts)
	if res.FailureReason != probe.ReasonHTTPStatusError {
		t.Fatalf("reason = %q, want http_status_error (302 != 200)", res.FailureReason)
	}
}

func TestRedirectDowngrade(t *testing.T) {
	t.Parallel()

	// Plain HTTP target to redirect to.
	plain := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(200)
	}))
	defer plain.Close()

	cert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), nil, localhostIPs())
	secure := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, plain.URL+"/", nethttp.StatusFound)
	}))
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	secure.StartTLS()
	defer secure.Close()

	// Trust the secure hop's cert so TLS inspection passes and the *downgrade*
	// (not an untrusted-cert failure) is what stops the probe.
	opts := baseOpts(secure.URL)
	opts.TLSRoots = certPool(t, cert)
	res := runProbe(t, opts)
	if res.FailureReason != probe.ReasonDowngrade {
		t.Fatalf("reason = %q, want downgrade", res.FailureReason)
	}
}

func TestConnectionRefused(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens on this port now

	res := runProbe(t, baseOpts(url))
	if res.FailureReason != probe.ReasonConnectionRefused {
		t.Fatalf("reason = %q, want connection_refused", res.FailureReason)
	}
}

func TestTimeout(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		select {
		case <-time.After(2 * time.Second):
			w.WriteHeader(200)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.Timeout = 100 * time.Millisecond
	res := runProbe(t, opts)
	if res.FailureReason != probe.ReasonTimeout {
		t.Fatalf("reason = %q, want timeout", res.FailureReason)
	}
}

func TestTLSValidCert(t *testing.T) {
	t.Parallel()

	cert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), nil, localhostIPs())
	srv := newTLSServer(t, cert, func(w nethttp.ResponseWriter, r *nethttp.Request) { w.WriteHeader(200) })
	defer srv.Close()

	// Trust the test cert so the default chain verification passes.
	opts := baseOpts(srv.URL)
	opts.TLSRoots = certPool(t, cert)
	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("expected success, got %q", res.FailureReason)
	}
	d := diag(t, res)
	if d.TLS == nil {
		t.Fatal("expected TLS diagnostics")
	}
	if !d.TLS.HostnameValid || !d.TLS.Valid {
		t.Errorf("expected valid+hostname-valid cert, got %+v", d.TLS)
	}
	if d.TLS.RemainingDays < 1 {
		t.Errorf("remaining days = %d, want >= 1", d.TLS.RemainingDays)
	}
}

func TestTLSUntrustedCertFails(t *testing.T) {
	t.Parallel()

	// A self-signed cert with valid dates and hostname, but no trusted CA.
	cert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), nil, localhostIPs())
	srv := newTLSServer(t, cert, func(w nethttp.ResponseWriter, r *nethttp.Request) { w.WriteHeader(200) })
	defer srv.Close()

	// Default policy: verify the chain against the system roots -> untrusted.
	res := runProbe(t, baseOpts(srv.URL))
	if res.Success {
		t.Fatal("expected an untrusted self-signed cert to fail by default")
	}
	if res.FailureReason != probe.ReasonCertificateInvalid {
		t.Errorf("reason = %q, want certificate_invalid", res.FailureReason)
	}
}

// TestTLSUntrustedAbortsBeforeRequest is the core of the security fix: against an
// untrusted certificate under default verification, the handshake must abort
// before the request is sent, so credentials never reach the (possibly MITM)
// server. The server records whether it was ever hit.
func TestTLSUntrustedAbortsBeforeRequest(t *testing.T) {
	t.Parallel()

	var (
		mu  sync.Mutex
		hit bool
	)
	cert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), nil, localhostIPs())
	srv := newTLSServer(t, cert, func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		hit = true
		mu.Unlock()
		w.WriteHeader(200)
	})
	defer srv.Close()

	opts := baseOpts(srv.URL) // default verify; the self-signed cert is untrusted
	opts.BasicAuthUser = "alice"
	opts.BasicAuthPass = "s3cret"
	res := runProbe(t, opts)
	if res.Success || res.FailureReason != probe.ReasonCertificateInvalid {
		t.Fatalf("expected certificate_invalid, got success=%v reason=%q", res.Success, res.FailureReason)
	}

	mu.Lock()
	defer mu.Unlock()
	if hit {
		t.Error("the request reached the server: credentials were sent before the untrusted cert was rejected")
	}
}

// TestTLSSkipVerifyNotAppliedCrossOrigin verifies the operator's TLS policy is
// origin-scoped: a skip-verify target that redirects to a *different* origin does
// not carry skip-verify to that hop, so its untrusted cert still fails.
func TestTLSSkipVerifyNotAppliedCrossOrigin(t *testing.T) {
	t.Parallel()

	cert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), nil, localhostIPs())
	// Cross-origin target (a different port -> different origin), untrusted.
	target := newTLSServer(t, cert, func(w nethttp.ResponseWriter, r *nethttp.Request) { w.WriteHeader(200) })
	defer target.Close()
	// Origin the operator configures (skip-verify), redirects to the target.
	origin := newTLSServer(t, cert, func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, target.URL, nethttp.StatusFound)
	})
	defer origin.Close()

	opts := baseOpts(origin.URL)
	opts.TLSSkipVerify = true // accepted for the origin only
	res := runProbe(t, opts)
	if res.Success {
		t.Fatal("skip-verify must not carry to the cross-origin redirect target")
	}
	if res.FailureReason != probe.ReasonCertificateInvalid {
		t.Errorf("reason = %q, want certificate_invalid on the cross-origin hop", res.FailureReason)
	}
}

func TestTLSSkipVerifyAcceptsUntrusted(t *testing.T) {
	t.Parallel()

	cert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), nil, localhostIPs())
	srv := newTLSServer(t, cert, func(w nethttp.ResponseWriter, r *nethttp.Request) { w.WriteHeader(200) })
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.TLSSkipVerify = true
	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("skip-verify should accept an untrusted cert, got %q", res.FailureReason)
	}
	// Diagnostics stay honest: an untrusted cert is reported Valid=false.
	if d := diag(t, res); d.TLS == nil || d.TLS.Valid {
		t.Errorf("expected Valid=false diagnostic for untrusted cert, got %+v", d.TLS)
	}
}

func TestTLSExpiredCert(t *testing.T) {
	t.Parallel()

	cert := makeCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), nil, localhostIPs())
	srv := newTLSServer(t, cert, func(w nethttp.ResponseWriter, r *nethttp.Request) { w.WriteHeader(200) })
	defer srv.Close()

	res := runProbe(t, baseOpts(srv.URL))
	if res.FailureReason != probe.ReasonCertificateExpired {
		t.Fatalf("reason = %q, want certificate_expired", res.FailureReason)
	}
	d := diag(t, res)
	if d.TLS == nil || d.TLS.RemainingDays >= 0 {
		t.Errorf("expected negative remaining days for expired cert, got %+v", d.TLS)
	}
}

func TestTLSWrongHostCert(t *testing.T) {
	t.Parallel()

	// Cert valid for a DNS name only, no localhost IP SAN → hostname mismatch.
	cert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), []string{"wrong.example"}, nil)
	srv := newTLSServer(t, cert, func(w nethttp.ResponseWriter, r *nethttp.Request) { w.WriteHeader(200) })
	defer srv.Close()

	res := runProbe(t, baseOpts(srv.URL))
	if res.FailureReason != probe.ReasonCertificateInvalid {
		t.Fatalf("reason = %q, want certificate_invalid", res.FailureReason)
	}
	if d := diag(t, res); d.TLS != nil && d.TLS.HostnameValid {
		t.Error("hostname should be invalid")
	}
}

func TestTLSToPlainPort(t *testing.T) {
	t.Parallel()

	plain := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {}))
	defer plain.Close()

	// Speak HTTPS to a plaintext port.
	httpsURL := strings.Replace(plain.URL, "http://", "https://", 1)
	res := runProbe(t, baseOpts(httpsURL))
	if res.FailureReason != probe.ReasonTLSError {
		t.Fatalf("reason = %q, want tls_error", res.FailureReason)
	}
}

// TestMaxBodyBytesBoundsSocketRead verifies the cap bounds bytes read off the
// wire, not just the returned buffer. The server streams an endless body; with
// the cap honoured the probe reads its cap, closes, and succeeds quickly. If the
// body were fully drained, the probe would instead run until its timeout.
func TestMaxBodyBytesBoundsSocketRead(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(200)
		flusher, _ := w.(nethttp.Flusher)
		chunk := []byte(strings.Repeat("A", 4096))
		for {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.MaxBodyBytes = 1024
	opts.Timeout = 2 * time.Second

	start := time.Now()
	res := runProbe(t, opts)
	elapsed := time.Since(start)

	if !res.Success {
		t.Fatalf("expected success, got reason %q after %v (body read appears unbounded)", res.FailureReason, elapsed)
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("probe took %v; the cap did not bound the socket read", elapsed)
	}
}

// TestTLSExpiredOnRedirectHop verifies TLS is inspected on every hop: an expired
// certificate on an intermediate redirecting host must fail, even though the
// final target is healthy.
func TestTLSExpiredOnRedirectHop(t *testing.T) {
	t.Parallel()

	final := newTLSServer(t,
		makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), nil, localhostIPs()),
		func(w nethttp.ResponseWriter, r *nethttp.Request) { w.WriteHeader(200) })
	defer final.Close()

	mid := newTLSServer(t,
		makeCert(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), nil, localhostIPs()),
		func(w nethttp.ResponseWriter, r *nethttp.Request) {
			nethttp.Redirect(w, r, final.URL+"/", nethttp.StatusFound)
		})
	defer mid.Close()

	res := runProbe(t, baseOpts(mid.URL))
	if res.FailureReason != probe.ReasonCertificateExpired {
		t.Fatalf("reason = %q, want certificate_expired on the intermediate hop", res.FailureReason)
	}
}

// newTLSServer starts an HTTPS test server presenting the given certificate.
func newTLSServer(t *testing.T, cert tls.Certificate, handler nethttp.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	return srv
}
