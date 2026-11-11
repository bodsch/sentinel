package tls

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

// countingServer wraps newTestServer's behaviour with a connection counter, so a
// test can tell whether an enumeration ran.
type countingServer struct {
	host  string
	port  int
	conns atomic.Int32
	ln    net.Listener
	// delayAfterFirst holds every connection but the first before its
	// handshake, which makes an enumeration slow and easy to tell apart. It is
	// fixed at construction: the accept loop reads it concurrently.
	delayAfterFirst time.Duration
}

// newCountingServer starts a TLS listener with cfg that completes handshakes and
// closes; every connection after the first waits delayAfterFirst before its
// handshake (zero: no delay).
func newCountingServer(t *testing.T, cfg *tls.Config, delayAfterFirst time.Duration) *countingServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().(*net.TCPAddr)
	s := &countingServer{host: addr.IP.String(), port: addr.Port, ln: ln, delayAfterFirst: delayAfterFirst}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			n := s.conns.Add(1)
			go func() {
				if n > 1 && s.delayAfterFirst > 0 {
					time.Sleep(s.delayAfterFirst)
				}
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_ = conn.Close()
			}()
		}
	}()
	return s
}

// enumOptions returns probe options for s with enumeration enabled.
func (s *countingServer) enumOptions(ca authority, e *EnumerateOptions) Options {
	return Options{
		Name: "enum", Host: s.host, Port: s.port, Timeout: 3 * time.Second,
		ServerName: testHost, Roots: ca.pool, Enumerate: e,
	}
}

func versionOf(t *testing.T, e *Enumeration, v uint16) VersionSupport {
	t.Helper()
	for _, vs := range e.Versions {
		if vs.Version == v {
			return vs
		}
	}
	t.Fatalf("version %s not enumerated", tls.VersionName(v))
	return VersionSupport{}
}

func cipherOf(t *testing.T, e *Enumeration, id uint16) CipherSupport {
	t.Helper()
	for _, c := range e.Ciphers {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("cipher %s not enumerated", tls.CipherSuiteName(id))
	return CipherSupport{}
}

func TestEnumerateModernServer(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Enumeration CA")
	srv := newCountingServer(t, serverConfig(ca.issue(t, leafOptions{})), 0) // TLS 1.2+

	res := runProbe(t, srv.enumOptions(ca, &EnumerateOptions{ForbidVersions: []uint16{tls.VersionTLS10, tls.VersionTLS11}, ForbidInsecureCiphers: true}))
	if !res.Success {
		t.Fatalf("probe failed: %q", res.FailureReason)
	}
	e := diag(t, res).Enumeration
	if e == nil || !e.Complete {
		t.Fatalf("enumeration = %+v, want a complete one", e)
	}
	for v, want := range map[uint16]bool{tls.VersionTLS10: false, tls.VersionTLS11: false, tls.VersionTLS12: true, tls.VersionTLS13: true} {
		if got := versionOf(t, e, v); !got.Known || got.Supported != want {
			t.Errorf("%s = %+v, want known supported=%v", tls.VersionName(v), got, want)
		}
	}
	if e.CipherVersion != tls.VersionTLS12 {
		t.Errorf("ciphers tried at %s, want TLS 1.2", tls.VersionName(e.CipherVersion))
	}
	if got := cipherOf(t, e, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256); !got.Supported {
		t.Errorf("ECDHE-ECDSA-AES128-GCM not accepted: %+v", got)
	}
	// An ECDSA certificate rules out every RSA-authenticated suite.
	if got := cipherOf(t, e, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256); !got.Known || got.Supported {
		t.Errorf("ECDHE-RSA suite = %+v, want known unsupported", got)
	}
	if n := len(e.InsecureSupported()); n != 0 {
		t.Errorf("%d insecure suites accepted by a default Go server", n)
	}
}

func TestEnumeratePolicy(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Enumeration CA")
	legacy := serverConfig(ca.issue(t, leafOptions{}))
	legacy.MinVersion = tls.VersionTLS10
	legacy.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, // insecure per crypto/tls
	}
	srv := newCountingServer(t, legacy, 0)

	tests := []struct {
		name string
		opts *EnumerateOptions
		want probe.FailureReason
	}{
		{"report only", &EnumerateOptions{}, probe.ReasonNone},
		{"forbid TLS 1.0", &EnumerateOptions{ForbidVersions: []uint16{tls.VersionTLS10}}, probe.ReasonTLSPolicyViolation},
		{"forbid a version not offered", &EnumerateOptions{ForbidVersions: []uint16{tls.VersionTLS13 + 1}}, probe.ReasonNone},
		{"forbid insecure ciphers", &EnumerateOptions{ForbidInsecureCiphers: true}, probe.ReasonTLSPolicyViolation},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res := runProbe(t, srv.enumOptions(ca, tc.opts))
			if res.FailureReason != tc.want {
				t.Fatalf("reason = %q, want %q", res.FailureReason, tc.want)
			}
			e := diag(t, res).Enumeration
			if got := versionOf(t, e, tls.VersionTLS10); !got.Supported {
				t.Errorf("TLS 1.0 = %+v, want supported", got)
			}
			insecure := e.InsecureSupported()
			if len(insecure) != 1 || insecure[0].ID != tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 {
				t.Errorf("insecure accepted = %+v, want exactly ECDHE-ECDSA-AES128-CBC-SHA256", insecure)
			}
		})
	}
}

// TestEnumerateInterval: an enumeration costs dozens of handshakes, so it runs
// once per interval and its result is reused — and still enforced — in between.
func TestEnumerateInterval(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Enumeration CA")
	legacy := serverConfig(ca.issue(t, leafOptions{}))
	legacy.MinVersion = tls.VersionTLS10
	srv := newCountingServer(t, legacy, 0)

	p, err := New(srv.enumOptions(ca, &EnumerateOptions{ForbidVersions: []uint16{tls.VersionTLS10}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first := p.Probe(t.Context())
	afterFirst := srv.conns.Load()
	second := p.Probe(t.Context())
	afterSecond := srv.conns.Load()

	if afterFirst < 10 {
		t.Fatalf("first run made %d connections, want an enumeration", afterFirst)
	}
	if afterSecond-afterFirst != 1 {
		t.Errorf("second run made %d connections, want only the main handshake", afterSecond-afterFirst)
	}
	if diag(t, first).Enumeration != diag(t, second).Enumeration {
		t.Error("second run did not reuse the cached enumeration")
	}
	if second.FailureReason != probe.ReasonTLSPolicyViolation {
		t.Errorf("second run reason = %q, want the cached violation enforced", second.FailureReason)
	}

	p.enumerate.Interval = time.Nanosecond
	p.Probe(t.Context())
	if srv.conns.Load()-afterSecond < 10 {
		t.Error("an elapsed interval did not trigger a new enumeration")
	}
}

// TestEnumerateKeepsMeasurementClean: the extra handshakes run after the
// measurement and must not inflate the reported duration.
func TestEnumerateKeepsMeasurementClean(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Enumeration CA")
	srv := newCountingServer(t, serverConfig(ca.issue(t, leafOptions{})), 100*time.Millisecond)
	p, err := New(srv.enumOptions(ca, &EnumerateOptions{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	start := time.Now()
	res := p.Probe(t.Context())
	wall := time.Since(start)
	// ~30 delayed handshakes on four workers take well over half a second; the
	// main handshake is not delayed.
	if wall < 500*time.Millisecond {
		t.Fatalf("wall time %v: the enumeration did not run", wall)
	}
	if res.Duration > 300*time.Millisecond {
		t.Errorf("duration %v includes the enumeration (wall %v)", res.Duration, wall)
	}
}

// TestEnumerateUnknownIsNotUnsupported: when the server becomes unreachable
// after the main probe, the entries stay unknown — neither "unsupported" in the
// metrics nor a policy hit.
func TestEnumerateUnknownIsNotUnsupported(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Enumeration CA")
	srv := newCountingServer(t, serverConfig(ca.issue(t, leafOptions{})), 0)
	p, err := New(srv.enumOptions(ca, &EnumerateOptions{ForbidVersions: []uint16{tls.VersionTLS10}}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	e := p.runEnumeration(t.Context(), "127.0.0.1:1") // nothing listens there
	if e.Complete {
		t.Fatal("enumeration against a dead endpoint reported complete")
	}
	for _, v := range e.Versions {
		if v.Known {
			t.Errorf("%s known without any answer", tls.VersionName(v.Version))
		}
	}
	p.lastEnum = e
	if r := p.enumerationReason(); r != probe.ReasonNone {
		t.Errorf("unknown entries produced %q, want no policy hit", r)
	}
}

func TestParseEnumVersion(t *testing.T) {
	t.Parallel()
	for s, want := range map[string]uint16{"1.0": tls.VersionTLS10, "1.1": tls.VersionTLS11, "1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13} {
		if got, ok := ParseEnumVersion(s); !ok || got != want {
			t.Errorf("ParseEnumVersion(%q) = %v %v", s, got, ok)
		}
	}
	if _, ok := ParseEnumVersion("SSLv3"); ok {
		t.Error("SSLv3 accepted")
	}
}

func TestCollectorEnumeration(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	rec := store.Record{
		Target: "legacy", Type: ProbeType,
		Result: probe.Result{Diagnostics: &Diagnostics{Enumeration: &Enumeration{
			At: at,
			Versions: []VersionSupport{
				{Version: tls.VersionTLS10, Supported: true, Known: true},
				{Version: tls.VersionTLS11}, // unknown
				{Version: tls.VersionTLS12, Supported: true, Known: true},
				{Version: tls.VersionTLS13, Known: true},
			},
			Ciphers: []CipherSupport{
				{Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Supported: true, Known: true},
				{Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Insecure: true, Supported: true, Known: true},
				{Name: "TLS_RSA_WITH_RC4_128_SHA", Insecure: true, Known: true},
			},
		}}},
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: []store.Record{rec}}))

	ver := func(v string) map[string]string { return map[string]string{"target": "legacy", "version": v} }
	if v, ok := gatherValue(t, reg, "sentinel_tls_version_supported", ver("TLS 1.0")); !ok || v != 1 {
		t.Errorf("TLS 1.0 = %v ok=%v, want 1", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_tls_version_supported", ver("TLS 1.3")); !ok || v != 0 {
		t.Errorf("TLS 1.3 = %v ok=%v, want 0", v, ok)
	}
	if _, ok := gatherValue(t, reg, "sentinel_tls_version_supported", ver("TLS 1.1")); ok {
		t.Error("unknown version emitted")
	}
	if v, ok := gatherValue(t, reg, "sentinel_tls_cipher_supported", map[string]string{"cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "insecure": "true"}); !ok || v != 1 {
		t.Errorf("3DES = %v ok=%v, want 1 with insecure=true", v, ok)
	}
	if _, ok := gatherValue(t, reg, "sentinel_tls_cipher_supported", map[string]string{"cipher": "TLS_RSA_WITH_RC4_128_SHA"}); ok {
		t.Error("refused suite emitted")
	}
	if v, ok := gatherValue(t, reg, "sentinel_tls_insecure_ciphers_supported", map[string]string{"target": "legacy"}); !ok || v != 1 {
		t.Errorf("insecure count = %v ok=%v, want 1", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_tls_enumeration_complete", map[string]string{"target": "legacy"}); !ok || v != 0 {
		t.Errorf("complete = %v ok=%v, want 0", v, ok)
	}
	if v, ok := gatherValue(t, reg, "sentinel_tls_enumeration_timestamp_seconds", map[string]string{"target": "legacy"}); !ok || v != float64(at.Unix()) {
		t.Errorf("timestamp = %v ok=%v", v, ok)
	}
}

// TestEnumerateTimeoutIsUnknown: a server that stalls the enumeration handshakes
// past the timeout gives no answer, which must not be read as "unsupported".
func TestEnumerateTimeoutIsUnknown(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Enumeration CA")
	srv := newCountingServer(t, serverConfig(ca.issue(t, leafOptions{})), 2*time.Second)
	opts := srv.enumOptions(ca, &EnumerateOptions{})
	opts.Timeout = 200 * time.Millisecond

	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("main probe failed: %q", res.FailureReason)
	}
	e := diag(t, res).Enumeration
	if e == nil || e.Complete {
		t.Fatalf("enumeration = %+v, want an incomplete one", e)
	}
	for _, v := range e.Versions {
		if v.Known {
			t.Errorf("%s known although every handshake timed out", tls.VersionName(v.Version))
		}
	}
}

// TestEnumerateLegacyOnlyServer: a server that speaks nothing but TLS 1.0 fails
// the regular probe (which offers TLS 1.2+), yet the enumeration must still run
// — such a server is precisely what it is for.
func TestEnumerateLegacyOnlyServer(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Enumeration CA")
	legacy := serverConfig(ca.issue(t, leafOptions{}))
	legacy.MinVersion, legacy.MaxVersion = tls.VersionTLS10, tls.VersionTLS10
	srv := newCountingServer(t, legacy, 0)

	res := runProbe(t, srv.enumOptions(ca, &EnumerateOptions{ForbidVersions: []uint16{tls.VersionTLS10}}))
	if res.Success {
		t.Fatal("regular probe succeeded against a TLS 1.0-only server")
	}
	e := diag(t, res).Enumeration
	if e == nil {
		t.Fatal("no enumeration although the endpoint was reachable")
	}
	if got := versionOf(t, e, tls.VersionTLS10); !got.Known || !got.Supported {
		t.Errorf("TLS 1.0 = %+v, want supported", got)
	}
	if e.CipherVersion != tls.VersionTLS10 {
		t.Errorf("ciphers tried at %s, want TLS 1.0", tls.VersionName(e.CipherVersion))
	}
}

// TestEnumerateInsecureOnlyServer: a server that offers nothing but an insecure
// suite must still be seen to support TLS 1.2 — otherwise the suite round never
// runs and the one thing worth reporting goes unseen.
func TestEnumerateInsecureOnlyServer(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Enumeration CA")
	cfg := serverConfig(ca.issue(t, leafOptions{}))
	cfg.MaxVersion = tls.VersionTLS12
	cfg.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}
	srv := newCountingServer(t, cfg, 0)

	res := runProbe(t, srv.enumOptions(ca, &EnumerateOptions{ForbidInsecureCiphers: true}))
	e := diag(t, res).Enumeration
	if got := versionOf(t, e, tls.VersionTLS12); !got.Supported {
		t.Fatalf("TLS 1.2 = %+v, want supported", got)
	}
	if n := len(e.InsecureSupported()); n != 1 {
		t.Errorf("insecure accepted = %d, want 1", n)
	}
	// The regular probe offers only secure suites, so its own handshake fails
	// first; that failure is the reason, the enumeration shows why.
	if res.Success || res.FailureReason == probe.ReasonTLSPolicyViolation {
		t.Errorf("reason = %q, want the regular handshake's failure", res.FailureReason)
	}
}

// TestEnumerateStopsOnShutdown: the enumeration runs on the scheduler's
// context, not the probe's timeout, so cancelling that context is the only
// thing that ends a slow run. If it were ignored, a shutdown would wait for
// every remaining handshake — rounds of four, each up to the target's timeout —
// and the service manager would kill the process mid-write.
func TestEnumerateStopsOnShutdown(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Enumeration CA")
	srv := newCountingServer(t, serverConfig(ca.issue(t, leafOptions{})), 30*time.Second)
	opts := srv.enumOptions(ca, &EnumerateOptions{})
	opts.Timeout = 20 * time.Second

	p, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		// The first connection is the regular probe; the second one is the
		// enumeration under way.
		for srv.conns.Load() < 2 {
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()

	done := make(chan probe.Result, 1)
	start := time.Now()
	go func() { done <- p.Probe(ctx) }()

	select {
	case res := <-done:
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("probe returned after %s, want promptly after the cancellation", elapsed)
		}
		if !res.Success {
			t.Errorf("reason = %q: a cancelled enumeration must not fail the regular probe", res.FailureReason)
		}
		e := diag(t, res).Enumeration
		if e == nil || e.Complete {
			t.Fatalf("enumeration = %+v, want an incomplete one", e)
		}
		for _, v := range e.Versions {
			if v.Known && !v.Supported {
				t.Errorf("%s reported unsupported, but its handshake was cut short by the cancellation", tls.VersionName(v.Version))
			}
		}
	case <-time.After(15 * time.Second):
		t.Fatal("probe kept enumerating after its context was cancelled; a shutdown would hang for minutes")
	}
}

// TestEnumerateThroughStartTLS: on a STARTTLS port every enumeration handshake
// has to upgrade first. Without that, each ClientHello lands on the plaintext
// SMTP dialogue, is refused, and counts as a definite "not supported" — the
// metrics would claim the mail server accepts no TLS version at all.
func TestEnumerateThroughStartTLS(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel STARTTLS Test CA")
	cfg := serverConfig(ca.issue(t, leafOptions{}))
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	srv := newStartTLSServer(t, cfg, smtpScript([]string{"mail.example", "STARTTLS"}, "220 go ahead\r\n"))

	opts := srv.options(StartTLSSMTP)
	opts.Roots = ca.pool
	opts.Enumerate = &EnumerateOptions{}

	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("main probe failed: %q", res.FailureReason)
	}
	e := diag(t, res).Enumeration
	if e == nil || !e.Complete {
		t.Fatalf("enumeration = %+v, want a complete one", e)
	}
	for v, want := range map[uint16]bool{tls.VersionTLS11: false, tls.VersionTLS12: true, tls.VersionTLS13: false} {
		if got := versionOf(t, e, v); got.Supported != want {
			t.Errorf("%s supported = %v, want %v", tls.VersionName(v), got.Supported, want)
		}
	}
	if got := cipherOf(t, e, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256); !got.Supported {
		t.Error("the suite the server negotiates is reported unsupported")
	}
}

// TestEnumerateWithClientCertificate: a server that requires a client
// certificate rejects every handshake without one. The enumeration must
// present the target's identity, or it reports a mutual-TLS endpoint as
// accepting no TLS 1.2 at all.
func TestEnumerateWithClientCertificate(t *testing.T) {
	t.Parallel()

	serverCA := newAuthority(t, "Sentinel Server CA")
	clientCA := newAuthority(t, "Sentinel Client CA")
	cfg := serverConfig(serverCA.issue(t, leafOptions{}))
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = clientCA.pool
	srv := newCountingServer(t, cfg, 0)

	clientCert := clientCA.issue(t, leafOptions{cn: "sentinel-client", client: true})
	opts := srv.enumOptions(serverCA, &EnumerateOptions{})
	opts.ClientCert = &clientCert

	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("main probe failed: %q", res.FailureReason)
	}
	e := diag(t, res).Enumeration
	if e == nil {
		t.Fatal("no enumeration")
	}
	if got := versionOf(t, e, tls.VersionTLS12); !got.Known || !got.Supported {
		t.Errorf("TLS 1.2 = %+v, want supported: the enumeration did not present the client certificate", got)
	}
	if e.CipherVersion != tls.VersionTLS12 {
		t.Errorf("cipher version = %s, want TLS 1.2", tls.VersionName(e.CipherVersion))
	}
}
