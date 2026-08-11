package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	nethttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// clientIdentity generates a CA and a client certificate signed by it, plus the
// pool a server needs to verify that client.
func clientIdentity(t *testing.T) (cert tls.Certificate, pool *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating client CA key: %v", err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Sentinel Client CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating client CA: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing client CA: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "sentinel-client"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating client certificate: %v", err)
	}

	pool = x509.NewCertPool()
	pool.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}, pool
}

// TestClientCertificateSentToTarget covers the ordinary mutual-TLS case: the
// target asks for an identity and receives the configured one.
func TestClientCertificateSentToTarget(t *testing.T) {
	t.Parallel()

	clientCert, clientCAs := clientIdentity(t)
	serverCert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), nil, localhostIPs())

	var presented atomic.Int32
	srv := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.TLS != nil {
			presented.Store(int32(len(r.TLS.PeerCertificates)))
		}
		w.WriteHeader(200)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	srv.StartTLS()
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.TLSRoots = certPool(t, serverCert)
	opts.TLSClientCert = &clientCert

	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("mutual TLS probe failed: %q", res.FailureReason)
	}
	if got := presented.Load(); got == 0 {
		t.Error("target received no client certificate")
	}
}

// TestClientCertificateOriginGuard is the security test for mutual TLS, aimed
// straight at the callback that enforces it.
//
// It is a unit test rather than an end-to-end one because the realistic leak
// cannot be staged locally: it needs a foreign origin whose certificate verifies
// against the *system* roots — any public HTTPS host — because only then does
// the handshake proceed far enough for the server to ask for a client
// certificate. Against a local test server the trust check already aborts the
// handshake first (see TestClientCertificateCrossOriginDefenceInDepth), which
// would make the test pass for the wrong reason.
func TestClientCertificateOriginGuard(t *testing.T) {
	t.Parallel()

	clientCert, _ := clientIdentity(t)
	p, err := New(baseOpts("https://target.example/"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.tlsClientCert = &clientCert

	t.Run("target's own origin receives the identity", func(t *testing.T) {
		p.hopSameOrigin = true
		got, cerr := p.clientCertificate(&tls.CertificateRequestInfo{})
		if cerr != nil {
			t.Fatalf("clientCertificate: %v", cerr)
		}
		if len(got.Certificate) == 0 {
			t.Error("no certificate offered to the target's own origin")
		}
	})

	t.Run("foreign origin receives nothing", func(t *testing.T) {
		p.hopSameOrigin = false
		got, cerr := p.clientCertificate(&tls.CertificateRequestInfo{})
		if cerr != nil {
			t.Fatalf("clientCertificate: %v", cerr)
		}
		if len(got.Certificate) != 0 {
			t.Error("client identity offered to a foreign origin")
		}
	})

	t.Run("no identity configured", func(t *testing.T) {
		bare, berr := New(baseOpts("https://target.example/"))
		if berr != nil {
			t.Fatalf("New: %v", berr)
		}
		bare.hopSameOrigin = true
		got, cerr := bare.clientCertificate(&tls.CertificateRequestInfo{})
		if cerr != nil || len(got.Certificate) != 0 {
			t.Errorf("got %v, %v; want an empty certificate and no error", got, cerr)
		}
	})
}

// TestClientCertificateCrossOriginDefenceInDepth shows the second, independent
// barrier: the operator's trust settings are origin-scoped too, so a redirect to
// an origin Sentinel does not trust publicly never completes a handshake at all
// — the client certificate is not even requested.
func TestClientCertificateCrossOriginDefenceInDepth(t *testing.T) {
	t.Parallel()

	clientCert, clientCAs := clientIdentity(t)

	// The foreign origin: asks every client for a certificate and records
	// whether one arrived.
	foreignCert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), nil, localhostIPs())
	var collected atomic.Int32
	foreign := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if r.TLS != nil {
			collected.Store(int32(len(r.TLS.PeerCertificates)))
		}
		w.WriteHeader(200)
	}))
	foreign.TLS = &tls.Config{
		Certificates: []tls.Certificate{foreignCert},
		// Request, not require: the probe must be able to complete the hop and
		// still hand over nothing.
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  clientCAs,
	}
	foreign.StartTLS()
	defer foreign.Close()

	// The target's own origin: redirects to the foreign one.
	targetCert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), nil, localhostIPs())
	target := newTLSServer(t, targetCert, func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, foreign.URL+"/", nethttp.StatusFound)
	})
	defer target.Close()

	// Trust both certificates via ca_file. The trust setting is origin-scoped as
	// well, so the foreign hop is still verified against the system roots — which
	// is the point being demonstrated.
	pool := certPool(t, targetCert)
	pool.AddCert(mustLeaf(t, foreignCert))

	opts := baseOpts(target.URL)
	opts.TLSRoots = pool
	opts.TLSClientCert = &clientCert

	res := runProbe(t, opts)
	if res.FailureReason != probe.ReasonCertificateInvalid {
		t.Fatalf("reason = %q, want certificate_invalid: the foreign origin must not inherit the target's trust settings", res.FailureReason)
	}
	if got := collected.Load(); got != 0 {
		t.Errorf("foreign origin received %d client certificate(s); the identity must never leave the target's origin", got)
	}
}

// mustLeaf parses the leaf certificate of a tls.Certificate.
func mustLeaf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return leaf
}

// TestServerNameOverridesVerificationHost covers the SNI override: the probe
// connects to 127.0.0.1 but validates — and announces — the configured name.
func TestServerNameOverridesVerificationHost(t *testing.T) {
	t.Parallel()

	const vhost = "virtual.example"

	// A certificate valid for the virtual host only, not for 127.0.0.1.
	cert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), []string{vhost}, nil)

	sni := make(chan string, 4)
	srv := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(200)
	}))
	base := &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case sni <- hello.ServerName:
			default:
			}
			return base, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.TLSRoots = certPool(t, cert)
	opts.TLSServerName = vhost

	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("probe with server_name failed: %q", res.FailureReason)
	}

	select {
	case got := <-sni:
		if got != vhost {
			t.Errorf("SNI = %q, want %q", got, vhost)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no handshake observed")
	}
}

// TestServerNameMismatchStillFails guards against the override turning into a
// blanket "accept anything": a name the certificate does not carry must fail.
func TestServerNameMismatchStillFails(t *testing.T) {
	t.Parallel()

	cert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), []string{"right.example"}, nil)
	srv := newTLSServer(t, cert, func(w nethttp.ResponseWriter, r *nethttp.Request) { w.WriteHeader(200) })
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.TLSRoots = certPool(t, cert)
	opts.TLSServerName = "wrong.example"

	if res := runProbe(t, opts); res.Success {
		t.Fatal("probe succeeded although the certificate is not valid for server_name")
	}
}

// TestMaxVersionCapsHandshake covers the compatibility use case on the HTTP
// path: a server requiring TLS 1.3 must fail a target capped at 1.2.
func TestMaxVersionCapsHandshake(t *testing.T) {
	t.Parallel()

	cert := makeCert(t, time.Now().Add(-time.Hour), time.Now().Add(48*time.Hour), nil, localhostIPs())
	srv := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(200)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	defer srv.Close()

	opts := baseOpts(srv.URL)
	opts.TLSRoots = certPool(t, cert)

	if res := runProbe(t, opts); !res.Success {
		t.Fatalf("uncapped probe failed: %q", res.FailureReason)
	}

	opts.TLSMaxVersion = tls.VersionTLS12
	if res := runProbe(t, opts); res.Success {
		t.Fatal("probe succeeded although the server requires TLS 1.3")
	}
}
