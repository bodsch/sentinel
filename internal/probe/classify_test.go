package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"syscall"
	"testing"
	"time"
)

// timeoutError is a net.Error that reports a timeout, standing in for a dial
// deadline that is not our own context deadline.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestClassifyNetworkError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want FailureReason
	}{
		{"nil", nil, ReasonNone},
		{"context deadline", context.DeadlineExceeded, ReasonTimeout},
		{"context cancelled", context.Canceled, ReasonTimeout},
		{"dns", &net.DNSError{Err: "no such host", Name: "nope.invalid"}, ReasonDNSError},
		{"refused", syscall.ECONNREFUSED, ReasonConnectionRefused},
		{"reset", syscall.ECONNRESET, ReasonConnectionRefused},
		{"host unreachable", syscall.EHOSTUNREACH, ReasonConnectionRefused},
		{"network unreachable", syscall.ENETUNREACH, ReasonConnectionRefused},
		{"tls record header", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, ReasonTLSError},
		{"x509 invalid", x509.CertificateInvalidError{Reason: x509.Expired}, ReasonTLSError},
		{"x509 hostname", x509.HostnameError{Host: "wrong.example"}, ReasonTLSError},
		{"x509 unknown authority", x509.UnknownAuthorityError{}, ReasonTLSError},
		{"tls alert (quic)", tls.AlertError(70), ReasonTLSError},
		{"remote alert", &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}, ReasonTLSError},
		{"other op error", &net.OpError{Op: "read", Err: errors.New("broken")}, ReasonNetworkError},
		{"local handshake error", errors.New("tls: server selected unsupported protocol version 301"), ReasonNetworkError},
		{"net timeout", timeoutError{}, ReasonTCPTimeout},
		{"unknown", errors.New("something else entirely"), ReasonNetworkError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyNetworkError(tc.err); got != tc.want {
				t.Errorf("ClassifyNetworkError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestClassifyNetworkErrorUnwraps covers the reason the function uses
// errors.Is/As throughout: the standard library hands back deeply nested causes,
// and a classification that only looked at the top-level error would degrade
// every one of them to network_error.
func TestClassifyNetworkErrorUnwraps(t *testing.T) {
	t.Parallel()

	nested := fmt.Errorf("dial tcp: %w",
		fmt.Errorf("connect: %w", syscall.ECONNREFUSED))

	if got := ClassifyNetworkError(nested); got != ReasonConnectionRefused {
		t.Errorf("wrapped ECONNREFUSED = %q, want connection_refused", got)
	}

	opErr := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &net.DNSError{Err: "no such host"},
	}
	if got := ClassifyNetworkError(opErr); got != ReasonDNSError {
		t.Errorf("OpError wrapping DNSError = %q, want dns_error", got)
	}
}

// TestClassifyNetworkErrorOrdering pins the precedence that matters in practice:
// our own deadline is reported as `timeout`, not as the `tcp_timeout` that the
// underlying net.Error would also match.
func TestClassifyNetworkErrorOrdering(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("read: %w", context.DeadlineExceeded)
	if got := ClassifyNetworkError(err); got != ReasonTimeout {
		t.Errorf("wrapped context deadline = %q, want timeout", got)
	}
}

// TestClassifyHandshakeError pins the one difference to ClassifyNetworkError:
// what the network classification leaves unrecognised is a TLS failure once the
// handshake produced it, while every recognised cause keeps its reason.
func TestClassifyHandshakeError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want FailureReason
	}{
		{"nil", nil, ReasonNone},
		{"local handshake error", errors.New("tls: server selected unsupported protocol version 301"), ReasonTLSError},
		{"server hung up", io.EOF, ReasonTLSError},
		{"wrapped eof", fmt.Errorf("handshake: %w", io.ErrUnexpectedEOF), ReasonTLSError},
		{"remote alert", &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}, ReasonTLSError},
		{"context deadline", context.DeadlineExceeded, ReasonTimeout},
		{"reset", syscall.ECONNRESET, ReasonConnectionRefused},
		{"net timeout", timeoutError{}, ReasonTCPTimeout},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyHandshakeError(tc.err); got != tc.want {
				t.Errorf("ClassifyHandshakeError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestClassifyRealHandshakeFailures runs genuine crypto/tls handshakes that the
// server refuses. The alert crypto/tls hands back has an unexported type and is
// recognised only by its net.OpError operation, so this test fails if a Go
// release changes how a received alert is reported.
func TestClassifyRealHandshakeFailures(t *testing.T) {
	t.Parallel()

	cert := selfSigned(t)
	tests := []struct {
		name   string
		server *tls.Config
		client *tls.Config
	}{
		{
			name:   "no shared version",
			server: &tls.Config{MinVersion: tls.VersionTLS13},
			client: &tls.Config{MaxVersion: tls.VersionTLS12},
		},
		{
			name: "no shared cipher suite",
			server: &tls.Config{
				MaxVersion:   tls.VersionTLS12,
				CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			},
			client: &tls.Config{
				MaxVersion:   tls.VersionTLS12,
				CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
			},
		},
		{
			name:   "client certificate required",
			server: &tls.Config{MaxVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert},
			client: &tls.Config{MaxVersion: tls.VersionTLS12},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.server.Certificates = []tls.Certificate{cert}
			tc.client.InsecureSkipVerify = true //nolint:gosec // the test server is self-signed; only the failure matters.

			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
			go func() {
				_ = tls.Server(serverConn, tc.server).HandshakeContext(t.Context())
				_ = serverConn.Close()
			}()

			err := tls.Client(clientConn, tc.client).HandshakeContext(t.Context())
			if err == nil {
				t.Fatal("handshake succeeded")
			}
			if got := ClassifyNetworkError(err); got != ReasonTLSError {
				t.Errorf("ClassifyNetworkError(%v) = %q, want tls_error", err, got)
			}
			if got := ClassifyHandshakeError(err); got != ReasonTLSError {
				t.Errorf("ClassifyHandshakeError(%v) = %q, want tls_error", err, got)
			}
		})
	}
}

// selfSigned returns a throwaway ECDSA certificate for an in-memory TLS server.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "classify.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
