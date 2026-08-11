package http

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	nethttp "net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/tlsdiag"
)

// stapledServer starts an HTTPS test server whose certificate is issued by a
// throwaway CA and which staples the given OCSP status to every handshake.
//
// Parameters:
//   - t: the test.
//   - status: an ocsp.Good / ocsp.Revoked / ocsp.Unknown status, or -1 to staple
//     nothing at all.
//
// It returns the running server and the root pool that trusts it. The server is
// closed when the test ends.
func stapledServer(t *testing.T, status int) (*httptest.Server, *x509.CertPool) {
	t.Helper()

	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Sentinel Staple Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	ca := createCert(t, caTmpl, caTmpl, &caKey.PublicKey, caKey)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           localhostIPs(),
	}
	leaf := createCert(t, leafTmpl, ca, &leafKey.PublicKey, caKey)

	serverCert := tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  leafKey,
	}
	if status >= 0 {
		tmpl := ocsp.Response{
			Status:       status,
			SerialNumber: leaf.SerialNumber,
			ThisUpdate:   now.Add(-time.Hour),
			NextUpdate:   now.Add(24 * time.Hour),
			IssuerHash:   crypto.SHA256,
		}
		if status == ocsp.Revoked {
			tmpl.RevokedAt = now.Add(-2 * time.Hour)
			tmpl.RevocationReason = ocsp.KeyCompromise
		}
		staple, err := ocsp.CreateResponse(ca, ca, tmpl, caKey)
		if err != nil {
			t.Fatalf("creating OCSP response: %v", err)
		}
		serverCert.OCSPStaple = staple
	}

	srv := newTLSServer(t, serverCert, func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(200)
	})
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return srv, pool
}

// createCert signs a certificate and returns it parsed.
func createCert(t *testing.T, tmpl, parent *x509.Certificate, pub any, priv crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	if err != nil {
		t.Fatalf("creating certificate %q: %v", tmpl.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate %q: %v", tmpl.Subject.CommonName, err)
	}
	return cert
}

// TestProbeReceivesOCSPStaple pins the assumption the whole stapling feature
// rests on: the response is already present in the ConnectionState when
// VerifyConnection runs, so it can be inspected without a second handshake or a
// request to the CA.
func TestProbeReceivesOCSPStaple(t *testing.T) {
	t.Parallel()

	srv, roots := stapledServer(t, ocsp.Good)
	opts := baseOpts(srv.URL)
	opts.TLSRoots = roots

	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("probe failed: %q", res.FailureReason)
	}
	d := diag(t, res)
	if d.TLS == nil || d.TLS.OCSP == nil {
		t.Fatalf("stapled OCSP response not captured: %+v", d.TLS)
	}
	if d.TLS.OCSP.Status != tlsdiag.StatusGood {
		t.Errorf("OCSP status = %q (%s), want good", d.TLS.OCSP.Status, d.TLS.OCSP.Error)
	}
	if d.TLS.OCSP.NextUpdate.IsZero() {
		t.Error("OCSP next update not captured")
	}
}

func TestProbeWithoutOCSPStaple(t *testing.T) {
	t.Parallel()

	srv, roots := stapledServer(t, -1)
	opts := baseOpts(srv.URL)
	opts.TLSRoots = roots

	res := runProbe(t, opts)
	if !res.Success {
		t.Fatalf("probe failed: %q", res.FailureReason)
	}
	if d := diag(t, res); d.TLS == nil || d.TLS.OCSP != nil {
		t.Errorf("OCSP = %+v, want nil when the server staples nothing", d.TLS.OCSP)
	}
}

// TestTLSPolicyViolations drives each policy through a real handshake to prove
// it is evaluated on the live connection, not just in a unit test.
func TestTLSPolicyViolations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		staple     int
		policy     *tlsdiag.Policy
		wantReason probe.FailureReason
	}{
		{
			name:       "certificate inside the renewal window",
			staple:     ocsp.Good,
			policy:     &tlsdiag.Policy{MinDaysRemaining: 365},
			wantReason: probe.ReasonCertificateExpiring,
		},
		{
			name:       "renewal window satisfied",
			staple:     ocsp.Good,
			policy:     &tlsdiag.Policy{MinDaysRemaining: 30},
			wantReason: probe.ReasonNone,
		},
		{
			name:       "stapling required but absent",
			staple:     -1,
			policy:     &tlsdiag.Policy{RequireOCSPStapling: true},
			wantReason: probe.ReasonTLSPolicyViolation,
		},
		{
			name:       "stapling required and present",
			staple:     ocsp.Good,
			policy:     &tlsdiag.Policy{RequireOCSPStapling: true},
			wantReason: probe.ReasonNone,
		},
		{
			name:       "revoked certificate fails a stapling policy",
			staple:     ocsp.Revoked,
			policy:     &tlsdiag.Policy{RequireOCSPStapling: true},
			wantReason: probe.ReasonTLSPolicyViolation,
		},
		{
			name:       "unexpected issuer",
			staple:     ocsp.Good,
			policy:     &tlsdiag.Policy{IssuerRegex: regexp.MustCompile(`^Let's Encrypt`)},
			wantReason: probe.ReasonTLSPolicyViolation,
		},
		{
			name:       "expected issuer",
			staple:     ocsp.Good,
			policy:     &tlsdiag.Policy{IssuerRegex: regexp.MustCompile(`Sentinel Staple Test CA`)},
			wantReason: probe.ReasonNone,
		},
		{
			name:       "minimum version satisfied",
			staple:     ocsp.Good,
			policy:     &tlsdiag.Policy{MinVersion: tls.VersionTLS12},
			wantReason: probe.ReasonNone,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv, roots := stapledServer(t, tc.staple)
			opts := baseOpts(srv.URL)
			opts.TLSRoots = roots
			opts.TLSPolicy = tc.policy

			res := runProbe(t, opts)
			if res.FailureReason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", res.FailureReason, tc.wantReason)
			}
			if res.Success != (tc.wantReason == probe.ReasonNone) {
				t.Errorf("success = %v for reason %q", res.Success, res.FailureReason)
			}

			// A policy breach must not cost the diagnostics: keeping the status
			// code, the timings and the certificate detail is exactly why the
			// policy is evaluated after the handshake rather than inside it.
			d := diag(t, res)
			if d.StatusCode != 200 {
				t.Errorf("status code = %d, want 200 even on a policy breach", d.StatusCode)
			}
			if d.TLS == nil {
				t.Error("TLS diagnostics missing on a policy breach")
			}
		})
	}
}

// TestTLSPolicyIgnoredWithoutTLS asserts a policy cannot fail a plain HTTP
// target, where there is no connection for it to describe.
func TestTLSPolicyIgnoredWithoutTLS(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.TLSPolicy = &tlsdiag.Policy{MinDaysRemaining: 365, RequireOCSPStapling: true}

	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("plain HTTP target failed a TLS policy: %q", res.FailureReason)
	}
}
