package http

import (
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"bodsch.me/sentinel/internal/probe"
)

func TestJSONPathValidationEndToEnd(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok","code":200}`))
	}))
	defer srv.Close()

	ok := "ok"
	opts := baseOpts(srv.URL)
	opts.JSONChecks = []JSONCheck{{Path: "$.status", Equals: &ok}, {Path: "$.code"}}
	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("expected JSON checks to pass, got %s", res.FailureReason)
	}

	nope := "nope"
	opts.JSONChecks = []JSONCheck{{Path: "$.status", Equals: &nope}}
	res := runProbe(t, opts)
	if res.Success {
		t.Fatal("expected a JSON mismatch failure")
	}
	if res.FailureReason != probe.ReasonValidationFailed {
		t.Errorf("reason = %q, want validation_failed", res.FailureReason)
	}
}

func TestPostBodySent(t *testing.T) {
	t.Parallel()

	var (
		mu     sync.Mutex
		method string
		body   string
		ctype  string
	)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		method = r.Method
		body = string(b)
		ctype = r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.Method = "POST"
	opts.Body = `{"ping":true}`
	opts.RequestHeaders = map[string]string{"Content-Type": "application/json"}
	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("probe failed: %s", res.FailureReason)
	}

	mu.Lock()
	defer mu.Unlock()
	if method != "POST" {
		t.Errorf("method = %q, want POST", method)
	}
	if body != `{"ping":true}` {
		t.Errorf("body = %q, want the configured payload", body)
	}
	if ctype != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ctype)
	}
}

// TestRedirectFollowedAsBodylessGet verifies a POST with a body that hits a
// redirect is followed as a GET with no body (avoids re-sending the body).
func TestRedirectFollowedAsBodylessGet(t *testing.T) {
	t.Parallel()

	var (
		mu      sync.Mutex
		bMethod string
		bBody   string
		bCtype  string
		bCalls  int
	)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/a":
			nethttp.Redirect(w, r, "/b", nethttp.StatusFound)
		case "/b":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			bMethod = r.Method
			bBody = string(b)
			bCtype = r.Header.Get("Content-Type")
			bCalls++
			mu.Unlock()
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL + "/a")
	opts.Method = "POST"
	opts.Body = "payload"
	opts.RequestHeaders = map[string]string{"Content-Type": "application/json"}
	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("probe failed: %s", res.FailureReason)
	}

	mu.Lock()
	defer mu.Unlock()
	if bCalls != 1 {
		t.Fatalf("/b hit %d times, want 1", bCalls)
	}
	if bMethod != "GET" {
		t.Errorf("redirect hop method = %q, want GET", bMethod)
	}
	if bBody != "" {
		t.Errorf("redirect hop body = %q, want empty (body not re-sent)", bBody)
	}
	if bCtype != "" {
		t.Errorf("redirect hop Content-Type = %q, want empty (no body, so no content type)", bCtype)
	}
}

// TestHeadRedirectStaysHead verifies the redirect reset preserves HEAD: a HEAD
// probe that follows a redirect must not silently downgrade to GET.
func TestHeadRedirectStaysHead(t *testing.T) {
	t.Parallel()

	var (
		mu      sync.Mutex
		bMethod string
		bCalls  int
	)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/a":
			nethttp.Redirect(w, r, "/b", nethttp.StatusFound)
		case "/b":
			mu.Lock()
			bMethod = r.Method
			bCalls++
			mu.Unlock()
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL + "/a")
	opts.Method = "HEAD"
	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("probe failed: %s", res.FailureReason)
	}

	mu.Lock()
	defer mu.Unlock()
	if bCalls != 1 {
		t.Fatalf("/b hit %d times, want 1", bCalls)
	}
	if bMethod != "HEAD" {
		t.Errorf("redirect hop method = %q, want HEAD (must not downgrade to GET)", bMethod)
	}
}

func TestRequestHeadersAndBasicAuth(t *testing.T) {
	t.Parallel()

	var (
		mu      sync.Mutex
		apiKey  string
		host    string
		user    string
		pass    string
		authOK  bool
		userAgt string
	)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		apiKey = r.Header.Get("X-Api-Key")
		host = r.Host
		user, pass, authOK = r.BasicAuth()
		userAgt = r.Header.Get("User-Agent")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.RequestHeaders = map[string]string{"X-Api-Key": "abc123", "Host": "vhost.example"}
	opts.BasicAuthUser = "alice"
	opts.BasicAuthPass = "s3cret"

	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("probe failed: %s", res.FailureReason)
	}

	mu.Lock()
	defer mu.Unlock()
	if apiKey != "abc123" {
		t.Errorf("X-Api-Key = %q, want abc123", apiKey)
	}
	if host != "vhost.example" {
		t.Errorf("Host = %q, want vhost.example (Host header must map to req.Host)", host)
	}
	if !authOK || user != "alice" || pass != "s3cret" {
		t.Errorf("basic auth = %q/%q ok=%v, want alice/s3cret", user, pass, authOK)
	}
	if !strings.HasPrefix(userAgt, "sentinel/") {
		t.Errorf("User-Agent = %q, want the sentinel default", userAgt)
	}
}

func TestRequestBearerToken(t *testing.T) {
	t.Parallel()

	var (
		mu   sync.Mutex
		auth string
	)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.BearerToken = "tok-xyz"
	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("probe failed: %s", res.FailureReason)
	}

	mu.Lock()
	defer mu.Unlock()
	if auth != "Bearer tok-xyz" {
		t.Errorf("Authorization = %q, want %q", auth, "Bearer tok-xyz")
	}
}

// TestWhitespaceBearerDoesNotOverrideAuthHeader verifies a whitespace-only bearer
// token is treated as unset at runtime (matching validation, which trims it), so
// it does not overwrite an explicit Authorization header with a malformed value.
func TestWhitespaceBearerDoesNotOverrideAuthHeader(t *testing.T) {
	t.Parallel()

	var (
		mu   sync.Mutex
		auth string
	)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.RequestHeaders = map[string]string{"Authorization": "Basic preset"}
	opts.BearerToken = "   " // whitespace only: must not override the header
	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("probe failed: %s", res.FailureReason)
	}

	mu.Lock()
	defer mu.Unlock()
	if auth != "Basic preset" {
		t.Errorf("Authorization = %q, want the preset header preserved (whitespace bearer must be unset)", auth)
	}
}

// TestAuthNotSentAcrossOriginRedirect is the security guard: credentials and
// custom headers must reach the target's own origin but NOT a redirect to a
// different origin. Two httptest servers bind distinct 127.0.0.1 ports, so the
// redirect crosses origins (different port) deterministically — no dependence on
// hostname resolution (localhost/IPv6).
func TestAuthNotSentAcrossOriginRedirect(t *testing.T) {
	t.Parallel()

	var (
		mu         sync.Mutex
		originAuth string
		targetAuth string
		targetKey  string
	)
	target := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		targetAuth = r.Header.Get("Authorization")
		targetKey = r.Header.Get("X-Api-Key")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer target.Close()

	origin := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		originAuth = r.Header.Get("Authorization")
		mu.Unlock()
		nethttp.Redirect(w, r, target.URL, nethttp.StatusFound)
	}))
	defer origin.Close()

	opts := baseOpts(origin.URL)
	opts.RequestHeaders = map[string]string{"X-Api-Key": "secret-key"}
	opts.BasicAuthUser = "alice"
	opts.BasicAuthPass = "s3cret"
	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("probe failed: %s", res.FailureReason)
	}

	mu.Lock()
	defer mu.Unlock()
	if originAuth == "" {
		t.Error("origin must receive the Authorization header")
	}
	if targetAuth != "" {
		t.Errorf("cross-origin redirect target must NOT receive Authorization, got %q", targetAuth)
	}
	if targetKey != "" {
		t.Errorf("cross-origin redirect target must NOT receive the custom header, got %q", targetKey)
	}
}

// TestAuthSentOnSameOriginRedirect verifies the guard is not over-strict: a
// redirect to a different path on the same origin still carries auth (otherwise a
// legitimate same-host redirect would fail with 401).
func TestAuthSentOnSameOriginRedirect(t *testing.T) {
	t.Parallel()

	var (
		mu     sync.Mutex
		bAuth  string
		bCalls int
	)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/a":
			nethttp.Redirect(w, r, "/b", nethttp.StatusFound)
		case "/b":
			mu.Lock()
			bAuth = r.Header.Get("Authorization")
			bCalls++
			mu.Unlock()
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL + "/a")
	opts.BearerToken = "tok-abc"
	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("probe failed: %s", res.FailureReason)
	}

	mu.Lock()
	defer mu.Unlock()
	if bCalls != 1 {
		t.Fatalf("/b hit %d times, want 1", bCalls)
	}
	if bAuth != "Bearer tok-abc" {
		t.Errorf("same-origin redirect must forward auth; /b Authorization = %q", bAuth)
	}
}
