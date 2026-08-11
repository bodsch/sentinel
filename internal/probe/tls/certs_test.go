package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// testHost is the name every generated server certificate is valid for. It is
// deliberately not "localhost": the probe connects to 127.0.0.1, so a test that
// wants the hostname to match must go through server_name — which is exactly the
// SNI path worth exercising.
const testHost = "sentinel.test"

// authority is a CA that can issue further certificates.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

// newAuthority creates a self-signed CA valid for a year.
func newAuthority(t testing.TB, cn string) authority {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	cert := signCert(t, tmpl, tmpl, &key.PublicKey, key)

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return authority{cert: cert, key: key, pool: pool}
}

// leafOptions tunes an issued end-entity certificate.
type leafOptions struct {
	// cn is the subject common name; empty means testHost.
	cn string
	// dnsNames overrides the DNS SANs; nil means [testHost].
	dnsNames []string
	// ips adds IP SANs.
	ips []net.IP
	// notBefore/notAfter override the validity window; zero means valid from an
	// hour ago for 90 days.
	notBefore, notAfter time.Time
	// client issues a client-authentication certificate instead of a server one.
	client bool
}

// issue creates an end-entity certificate signed by the authority and returns it
// as a tls.Certificate ready to be installed on a server or client.
func (a authority) issue(t testing.TB, opts leafOptions) tls.Certificate {
	t.Helper()

	now := time.Now()
	if opts.cn == "" {
		opts.cn = testHost
	}
	if opts.notBefore.IsZero() {
		opts.notBefore = now.Add(-time.Hour)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = now.Add(90 * 24 * time.Hour)
	}
	if opts.dnsNames == nil && !opts.client {
		opts.dnsNames = []string{testHost}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	usage := x509.ExtKeyUsageServerAuth
	if opts.client {
		usage = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: opts.cn},
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{usage},
		BasicConstraintsValid: true,
		DNSNames:              opts.dnsNames,
		IPAddresses:           opts.ips,
	}
	cert := signCert(t, tmpl, a.cert, &key.PublicKey, a.key)

	return tls.Certificate{
		Certificate: [][]byte{cert.Raw, a.cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

// signCert creates and re-parses a certificate.
func signCert(t testing.TB, tmpl, parent *x509.Certificate, pub any, priv crypto.Signer) *x509.Certificate {
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

// testServer is a TLS listener that accepts handshakes and closes immediately
// afterwards — enough for a probe that speaks no application protocol.
type testServer struct {
	// host and port are the listening address, ready to be put into Options.
	host string
	port int
	// sniNames records the SNI value of every handshake seen, so a test can
	// assert what the probe actually sent.
	sniNames chan string
}

// newTestServer starts a TLS listener with the given configuration and stops it
// when the test ends.
func newTestServer(t testing.TB, cfg *tls.Config) *testServer {
	t.Helper()

	srv := &testServer{sniNames: make(chan string, 16)}

	// Record the SNI name of each handshake without changing the configuration.
	base := cfg.Clone()
	cfg = base.Clone()
	cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		select {
		case srv.sniNames <- hello.ServerName:
		default:
		}
		return base, nil
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr := ln.Addr().(*net.TCPAddr)
	srv.host = addr.IP.String()
	srv.port = addr.Port

	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				// Drive the handshake, then close: the probe reads nothing.
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				_ = conn.Close()
			}()
		}
	}()
	return srv
}

// lastSNI returns the SNI name of the most recent handshake, or "" if none was
// recorded.
func (s *testServer) lastSNI(t testing.TB) string {
	t.Helper()
	select {
	case name := <-s.sniNames:
		return name
	case <-time.After(2 * time.Second):
		t.Fatal("no handshake observed")
		return ""
	}
}

// serverConfig builds a server TLS configuration presenting cert.
func serverConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}
