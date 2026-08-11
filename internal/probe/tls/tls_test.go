package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"regexp"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/tlsdiag"
)

// baseOptions returns options pointing at the test server. The probe connects to
// 127.0.0.1 while the certificate is issued for testHost, so server_name is set
// — the same shape as probing a virtual host by IP.
func baseOptions(srv *testServer) Options {
	return Options{
		Name:       "test",
		Host:       srv.host,
		Port:       srv.port,
		Timeout:    5 * time.Second,
		ServerName: testHost,
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

// diag extracts the TLS diagnostics from a result.
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

	ca := newAuthority(t, "Sentinel Probe Test CA")
	srv := newTestServer(t, serverConfig(ca.issue(t, leafOptions{})))

	opts := baseOptions(srv)
	opts.Roots = ca.pool
	res := runProbe(t, opts)

	if !res.Success {
		t.Fatalf("probe failed: %q", res.FailureReason)
	}
	d := diag(t, res)
	if d.TLS == nil {
		t.Fatal("no TLS diagnostics")
	}
	if !d.TLS.Valid || !d.TLS.HostnameValid || !d.TLS.ChainVerified {
		t.Errorf("certificate not fully valid: %+v", d.TLS)
	}
	if d.Endpoint == "" {
		t.Error("endpoint not recorded")
	}
	if d.ServerName != testHost {
		t.Errorf("server name = %q, want %q", d.ServerName, testHost)
	}
	// The chain is leaf + CA; the CA is also the root, so the verified chain is
	// two certificates long.
	if d.TLS.ChainLength != 2 {
		t.Errorf("chain length = %d, want 2", d.TLS.ChainLength)
	}
}

// TestProbeMeasuresPhasesSeparately covers the reason the probe resolves names
// itself: "slow to resolve" and "slow to connect" must be distinguishable.
func TestProbeMeasuresPhasesSeparately(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Probe Test CA")
	srv := newTestServer(t, serverConfig(ca.issue(t, leafOptions{})))

	opts := baseOptions(srv)
	opts.Roots = ca.pool
	res := runProbe(t, opts)

	if !res.Success {
		t.Fatalf("probe failed: %q", res.FailureReason)
	}
	tm := res.Timings
	if tm.Connect <= 0 {
		t.Errorf("connect duration = %v, want > 0", tm.Connect)
	}
	if tm.TLS <= 0 {
		t.Errorf("handshake duration = %v, want > 0", tm.TLS)
	}
	// DNS may legitimately be ~0 for an IP literal, but the phases together can
	// never exceed the total.
	if sum := tm.DNS + tm.Connect + tm.TLS; sum > res.Duration {
		t.Errorf("phases sum to %v, exceeding the total %v", sum, res.Duration)
	}
}

func TestProbeCertificateFailures(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tests := []struct {
		name       string
		leaf       leafOptions
		serverName string
		want       probe.FailureReason
	}{
		{
			name: "expired",
			leaf: leafOptions{notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour)},
			want: probe.ReasonCertificateExpired,
		},
		{
			name: "not yet valid",
			leaf: leafOptions{notBefore: now.Add(24 * time.Hour), notAfter: now.Add(48 * time.Hour)},
			want: probe.ReasonCertificateInvalid,
		},
		{
			name:       "hostname mismatch",
			leaf:       leafOptions{dnsNames: []string{"other.test"}},
			serverName: testHost,
			want:       probe.ReasonCertificateInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ca := newAuthority(t, "Sentinel Probe Test CA")
			srv := newTestServer(t, serverConfig(ca.issue(t, tc.leaf)))

			opts := baseOptions(srv)
			opts.Roots = ca.pool
			res := runProbe(t, opts)

			if res.FailureReason != tc.want {
				t.Fatalf("reason = %q, want %q", res.FailureReason, tc.want)
			}
			// Diagnostics must survive a rejected certificate — that is when an
			// operator needs them most.
			if d := diag(t, res); d.TLS == nil {
				t.Error("no TLS diagnostics for a rejected certificate")
			}
		})
	}
}

func TestProbeUntrustedCertificate(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Probe Test CA")
	srv := newTestServer(t, serverConfig(ca.issue(t, leafOptions{})))

	// An empty pool trusts nothing.
	opts := baseOptions(srv)
	opts.Roots = x509.NewCertPool()
	res := runProbe(t, opts)

	if res.FailureReason != probe.ReasonCertificateInvalid {
		t.Fatalf("reason = %q, want certificate_invalid", res.FailureReason)
	}
	if d := diag(t, res); d.TLS == nil || d.TLS.ChainVerified {
		t.Errorf("chain reported as verified against an empty pool: %+v", d.TLS)
	}
}

func TestProbeSkipVerify(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Probe Test CA")
	srv := newTestServer(t, serverConfig(ca.issue(t, leafOptions{})))

	opts := baseOptions(srv)
	opts.Roots = x509.NewCertPool()
	opts.SkipVerify = true
	res := runProbe(t, opts)

	if !res.Success {
		t.Fatalf("skip-verify probe failed: %q", res.FailureReason)
	}
	// The report stays honest: accepted, but not trusted.
	if d := diag(t, res); d.TLS.Valid || d.TLS.ChainVerified {
		t.Errorf("skip-verify must not fake trust: %+v", d.TLS)
	}
}

// TestProbeSendsSNI covers the option's reason for existing: against an IP
// address Go sends no SNI at all, so a virtual host would answer with its
// default certificate.
func TestProbeSendsSNI(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Probe Test CA")
	srv := newTestServer(t, serverConfig(ca.issue(t, leafOptions{})))

	t.Run("server_name is sent", func(t *testing.T) {
		opts := baseOptions(srv)
		opts.Roots = ca.pool
		if res := runProbe(t, opts); !res.Success {
			t.Fatalf("probe failed: %q", res.FailureReason)
		}
		if got := srv.lastSNI(t); got != testHost {
			t.Errorf("SNI = %q, want %q", got, testHost)
		}
	})

	t.Run("no SNI for a bare IP", func(t *testing.T) {
		opts := baseOptions(srv)
		opts.ServerName = ""
		opts.SkipVerify = true // 127.0.0.1 is not in the certificate
		if res := runProbe(t, opts); !res.Success {
			t.Fatalf("probe failed: %q", res.FailureReason)
		}
		if got := srv.lastSNI(t); got != "" {
			t.Errorf("SNI = %q, want empty for an IP literal", got)
		}
	})
}

func TestProbeMutualTLS(t *testing.T) {
	t.Parallel()

	serverCA := newAuthority(t, "Sentinel Server CA")
	clientCA := newAuthority(t, "Sentinel Client CA")

	cfg := serverConfig(serverCA.issue(t, leafOptions{}))
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = clientCA.pool
	srv := newTestServer(t, cfg)

	t.Run("with client certificate", func(t *testing.T) {
		clientCert := clientCA.issue(t, leafOptions{cn: "sentinel-client", client: true})
		opts := baseOptions(srv)
		opts.Roots = serverCA.pool
		opts.ClientCert = &clientCert

		if res := runProbe(t, opts); !res.Success {
			t.Fatalf("mTLS probe failed: %q", res.FailureReason)
		}
	})

	t.Run("without client certificate", func(t *testing.T) {
		opts := baseOptions(srv)
		opts.Roots = serverCA.pool

		res := runProbe(t, opts)
		if res.Success {
			t.Fatal("probe succeeded without the required client certificate")
		}
		// The server rejects after our side finished, so the exact reason is
		// transport-level; what matters is that it fails rather than passing.
		if res.FailureReason == probe.ReasonNone {
			t.Error("failure reason not set")
		}
	})
}

func TestProbeALPN(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Probe Test CA")
	cfg := serverConfig(ca.issue(t, leafOptions{}))
	cfg.NextProtos = []string{"h2", "http/1.1"}
	srv := newTestServer(t, cfg)

	t.Run("negotiated", func(t *testing.T) {
		opts := baseOptions(srv)
		opts.Roots = ca.pool
		opts.ALPN = []string{"h2"}

		res := runProbe(t, opts)
		if !res.Success {
			t.Fatalf("probe failed: %q", res.FailureReason)
		}
		d := diag(t, res)
		if d.ALPN != "h2" {
			t.Errorf("negotiated protocol = %q, want h2", d.ALPN)
		}
		// The diagnostics feed the shared collector, so the info must reach it.
		if d.TLS.ALPN != "h2" {
			t.Errorf("tlsdiag ALPN = %q, want h2", d.TLS.ALPN)
		}
	})

	t.Run("not offered", func(t *testing.T) {
		opts := baseOptions(srv)
		opts.Roots = ca.pool

		res := runProbe(t, opts)
		if !res.Success {
			t.Fatalf("probe failed: %q", res.FailureReason)
		}
		if d := diag(t, res); d.ALPN != "" {
			t.Errorf("negotiated protocol = %q, want empty when none was offered", d.ALPN)
		}
	})
}

// TestProbeMaxVersion covers the compatibility test the option exists for: a
// server that requires TLS 1.3 must fail a target pinned to 1.2.
func TestProbeMaxVersion(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Probe Test CA")
	cfg := serverConfig(ca.issue(t, leafOptions{}))
	cfg.MinVersion = tls.VersionTLS13
	srv := newTestServer(t, cfg)

	t.Run("capped below what the server accepts", func(t *testing.T) {
		opts := baseOptions(srv)
		opts.Roots = ca.pool
		opts.MaxVersion = tls.VersionTLS12

		if res := runProbe(t, opts); res.Success {
			t.Fatal("probe succeeded although the server requires TLS 1.3")
		}
	})

	t.Run("uncapped", func(t *testing.T) {
		opts := baseOptions(srv)
		opts.Roots = ca.pool

		res := runProbe(t, opts)
		if !res.Success {
			t.Fatalf("probe failed: %q", res.FailureReason)
		}
		if d := diag(t, res); d.TLS.VersionName != "TLS 1.3" {
			t.Errorf("version = %q, want TLS 1.3", d.TLS.VersionName)
		}
	})
}

func TestProbePolicy(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel Probe Test CA")
	srv := newTestServer(t, serverConfig(ca.issue(t, leafOptions{})))

	tests := []struct {
		name   string
		policy *tlsdiag.Policy
		want   probe.FailureReason
	}{
		{
			name:   "renewal window satisfied",
			policy: &tlsdiag.Policy{MinDaysRemaining: 30},
			want:   probe.ReasonNone,
		},
		{
			// The test certificate is valid for 90 days.
			name:   "inside the renewal window",
			policy: &tlsdiag.Policy{MinDaysRemaining: 365},
			want:   probe.ReasonCertificateExpiring,
		},
		{
			name:   "stapling required but absent",
			policy: &tlsdiag.Policy{RequireOCSPStapling: true},
			want:   probe.ReasonTLSPolicyViolation,
		},
		{
			name:   "unexpected issuer",
			policy: &tlsdiag.Policy{IssuerRegex: regexp.MustCompile(`^Let's Encrypt`)},
			want:   probe.ReasonTLSPolicyViolation,
		},
		{
			name:   "expected issuer",
			policy: &tlsdiag.Policy{IssuerRegex: regexp.MustCompile(`Sentinel Probe Test CA`)},
			want:   probe.ReasonNone,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			opts := baseOptions(srv)
			opts.Roots = ca.pool
			opts.Policy = tc.policy

			res := runProbe(t, opts)
			if res.FailureReason != tc.want {
				t.Fatalf("reason = %q, want %q", res.FailureReason, tc.want)
			}
			// A policy breach must not cost the diagnostics.
			if d := diag(t, res); d.TLS == nil {
				t.Error("TLS diagnostics missing on a policy breach")
			}
		})
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	t.Parallel()

	// Bind and immediately release a port to get one that is very likely closed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()

	opts := Options{
		Name:       "refused",
		Host:       addr.IP.String(),
		Port:       addr.Port,
		Timeout:    2 * time.Second,
		SkipVerify: true,
	}
	res := runProbe(t, opts)

	if res.Success {
		t.Fatal("probe succeeded against a closed port")
	}
	if res.FailureReason != probe.ReasonConnectionRefused {
		t.Errorf("reason = %q, want connection_refused", res.FailureReason)
	}
	if d := diag(t, res); d.TLS != nil {
		t.Error("TLS diagnostics reported although no handshake happened")
	}
}

func TestProbePlaintextPort(t *testing.T) {
	t.Parallel()

	// A plain TCP listener that never speaks TLS: the handshake must fail as a
	// TLS error rather than as a certificate problem.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_, _ = conn.Write([]byte("220 plaintext service ready\r\n"))
			_ = conn.Close()
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	res := runProbe(t, Options{
		Name:       "plaintext",
		Host:       addr.IP.String(),
		Port:       addr.Port,
		Timeout:    3 * time.Second,
		SkipVerify: true,
	})

	if res.Success {
		t.Fatal("probe succeeded against a plaintext port")
	}
	if res.FailureReason != probe.ReasonTLSError {
		t.Errorf("reason = %q, want tls_error", res.FailureReason)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts Options
	}{
		{"no timeout", Options{Name: "x", Host: "example.org", Port: 443}},
		{"empty host", Options{Name: "x", Port: 443, Timeout: time.Second}},
		{"blank host", Options{Name: "x", Host: "   ", Port: 443, Timeout: time.Second}},
		{"port zero", Options{Name: "x", Host: "example.org", Timeout: time.Second}},
		{"port too high", Options{Name: "x", Host: "example.org", Port: 70000, Timeout: time.Second}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tc.opts); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestProbeType(t *testing.T) {
	t.Parallel()

	p, err := New(Options{Name: "x", Host: "example.org", Port: 443, Timeout: time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Type() != ProbeType || ProbeType != "tls" {
		t.Errorf("Type() = %q, want tls", p.Type())
	}
}
