package http

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"bodsch.me/sentinel/internal/probe"
)

func TestIsPrivateAddr(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"127.0.0.1":        true, // loopback
		"127.1.2.3":        true,
		"::1":              true,
		"10.1.2.3":         true, // RFC 1918
		"172.16.0.1":       true,
		"172.31.255.255":   true,
		"192.168.1.1":      true,
		"fc00::1":          true, // RFC 4193
		"fd12:3456::1":     true,
		"169.254.169.254":  true, // link-local, cloud metadata
		"fe80::1":          true,
		"0.0.0.0":          true, // unspecified
		"::":               true,
		"0.1.2.3":          true, // "this network"
		"100.64.0.1":       true, // carrier-grade NAT
		"100.127.255.254":  true,
		"::ffff:127.0.0.1": true, // IPv4-mapped loopback
		"::ffff:10.0.0.1":  true,
		"224.0.0.251":      true, // link-local multicast (mDNS)
		"ff02::1":          true,
		"8.8.8.8":          false,
		"1.1.1.1":          false,
		"172.32.0.1":       false, // just outside 172.16/12
		"100.128.0.1":      false, // just outside 100.64/10
		"2001:4860::8888":  false,
		"::ffff:8.8.8.8":   false,
	}
	for in, want := range cases {
		if got := isPrivateAddr(netip.MustParseAddr(in)); got != want {
			t.Errorf("isPrivateAddr(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestHostKey(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"http://Example.COM/x":         "example.com",
		"https://example.com.:8443/":   "example.com",
		"http://[::1]:8080/":           "::1",
		"http://127.0.0.1:9/":          "127.0.0.1",
		"https://user@host.example/p?": "host.example",
	}
	for in, want := range cases {
		if got := hostKey(in); got != want {
			t.Errorf("hostKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// redirectingServer redirects /a to location and counts requests to /b.
func redirectingServer(t *testing.T, location func(srv *httptest.Server) string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hitsB atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		switch r.URL.Path {
		case "/a":
			nethttp.Redirect(w, r, location(srv), nethttp.StatusFound)
		case "/b":
			hitsB.Add(1)
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hitsB
}

// localhostHop returns the server's own /b under the name "localhost": a
// different host than the 127.0.0.1 target URL, resolving to loopback.
func localhostHop(s *httptest.Server) string {
	u, _ := url.Parse(s.URL)
	return "http://localhost:" + u.Port() + "/b"
}

// TestBlockPrivateRedirectsResolvedName is the core promise: a redirect to a
// different host is checked on the address the dialer resolves, so a harmless-
// looking name that points at loopback is refused before any request is sent.
func TestBlockPrivateRedirectsResolvedName(t *testing.T) {
	t.Parallel()

	srv, hitsB := redirectingServer(t, localhostHop)

	opts := baseOpts(srv.URL + "/a") // http://127.0.0.1:port/a
	opts.BlockPrivateRedirects = true
	res := runProbe(t, opts)

	if res.FailureReason != probe.ReasonRedirectBlocked {
		t.Fatalf("reason = %q, want redirect_blocked", res.FailureReason)
	}
	if n := hitsB.Load(); n != 0 {
		t.Errorf("blocked hop received %d request(s), want 0", n)
	}
	d := diag(t, res)
	if !strings.HasPrefix(d.FinalURL, "http://localhost:") {
		t.Errorf("final URL = %q, want the refused hop", d.FinalURL)
	}
	if len(d.Redirects) != 1 {
		t.Errorf("redirect chain len = %d, want 1", len(d.Redirects))
	}
}

// TestBlockPrivateRedirectsOffByDefault pins the opt-in: without the flag the
// same redirect is followed, so existing configurations keep working.
func TestBlockPrivateRedirectsOffByDefault(t *testing.T) {
	t.Parallel()

	srv, hitsB := redirectingServer(t, localhostHop)

	res := runProbe(t, baseOpts(srv.URL+"/a"))
	if !res.Success {
		t.Fatalf("expected success, got %q", res.FailureReason)
	}
	if hitsB.Load() != 1 {
		t.Errorf("hop /b hits = %d, want 1", hitsB.Load())
	}
}

// TestBlockPrivateRedirectsSameHost verifies that the target's own host is
// never guarded: an internal target redirecting within itself — here to a
// different port on the same host — must keep working.
func TestBlockPrivateRedirectsSameHost(t *testing.T) {
	t.Parallel()

	other, hitsOther := redirectingServer(t, func(*httptest.Server) string { return "/b" })
	srv, _ := redirectingServer(t, func(*httptest.Server) string { return other.URL + "/b" })

	opts := baseOpts(srv.URL + "/a")
	opts.BlockPrivateRedirects = true
	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("expected success for a same-host redirect, got %q", res.FailureReason)
	}
	if hitsOther.Load() != 1 {
		t.Errorf("same-host hop hits = %d, want 1", hitsOther.Load())
	}
}

// TestBlockPrivateRedirectsChecksDialedAddress replaces the predicate to show
// that the guard sees the address actually dialed — the property that makes it
// immune to DNS rebinding — and that an allowed address is followed normally.
func TestBlockPrivateRedirectsChecksDialedAddress(t *testing.T) {
	t.Parallel()

	srv, hitsB := redirectingServer(t, localhostHop)

	opts := baseOpts(srv.URL + "/a")
	opts.BlockPrivateRedirects = true
	p, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var mu sync.Mutex
	var seen []netip.Addr
	p.blockedAddr = func(a netip.Addr) bool {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, a)
		return false
	}

	res := p.Probe(context.Background())
	if !res.Success {
		t.Fatalf("expected success, got %q", res.FailureReason)
	}
	if hitsB.Load() != 1 {
		t.Errorf("hop /b hits = %d, want 1", hitsB.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, a := range seen {
		if a.Unmap() == netip.MustParseAddr("127.0.0.1") {
			found = true
		}
	}
	if !found {
		t.Errorf("guard saw %v, want the dialed address 127.0.0.1", seen)
	}
}

// proxyServer is a minimal forward proxy stand-in: it answers absolute-form
// requests itself. Requests for host "target.test" path /a are redirected to
// next; everything else is answered 200 and recorded.
func proxyServer(t *testing.T, next string) (*httptest.Server, *sync.Map) {
	t.Helper()
	var hits sync.Map
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.Host == "target.test" && r.URL.Path == "/a" {
			nethttp.Redirect(w, r, next, nethttp.StatusFound)
			return
		}
		hits.Store(r.Host+r.URL.Path, true)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// proxiedProber builds a guarded prober that sends every request through proxy.
func proxiedProber(t *testing.T, proxy *httptest.Server) *Prober {
	t.Helper()
	opts := baseOpts("http://target.test/a")
	opts.BlockPrivateRedirects = true
	p, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxyURL, _ := url.Parse(proxy.URL)
	p.transport.Proxy = nethttp.ProxyURL(proxyURL)
	return p
}

// TestBlockPrivateRedirectsViaProxy covers the proxy fallback: the dialer only
// sees the (loopback) proxy, so the hop's host is resolved up front instead and
// a name pointing at loopback is refused without reaching the proxy.
func TestBlockPrivateRedirectsViaProxy(t *testing.T) {
	t.Parallel()

	proxy, hits := proxyServer(t, "http://localhost/b")
	res := proxiedProber(t, proxy).Probe(context.Background())

	if res.FailureReason != probe.ReasonRedirectBlocked {
		t.Fatalf("reason = %q, want redirect_blocked", res.FailureReason)
	}
	if _, ok := hits.Load("localhost/b"); ok {
		t.Error("blocked hop was sent to the proxy")
	}
}

// TestBlockPrivateRedirectsViaProxyUnresolvable shows the two other halves of
// the proxy path: the proxy itself sits on loopback and must not be blocked by
// the dial guard, and a hop whose name does not resolve locally is left to the
// proxy rather than refused.
func TestBlockPrivateRedirectsViaProxyUnresolvable(t *testing.T) {
	t.Parallel()

	proxy, hits := proxyServer(t, "http://sentinel-egress-test.invalid/b")
	res := proxiedProber(t, proxy).Probe(context.Background())

	if !res.Success {
		t.Fatalf("expected success, got %q", res.FailureReason)
	}
	if _, ok := hits.Load("sentinel-egress-test.invalid/b"); !ok {
		t.Error("hop was not forwarded to the proxy")
	}
}
