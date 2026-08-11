package http

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"
)

// newTransport builds the HTTP transport used for probing. Design points:
//
//   - DisableKeepAlives: a fresh connection per request so every DNS/TCP/TLS
//     phase is measured (no pooling/reuse).
//   - Proxy from the environment (HTTP_PROXY/HTTPS_PROXY).
//   - InsecureSkipVerify with a VerifyConnection callback: the standard chain
//     check is disabled so it cannot auto-fail (keeping diagnostics available),
//     and verify performs our own inspection *during the handshake*. Returning an
//     error from it aborts the handshake before any request (and credentials) is
//     sent, so an untrusted certificate never receives the request body/auth.
//     This is NOT "TLS off": the certificate is inspected and, by default,
//     rejected if untrusted.
//   - Secondary, non-configurable safety timeouts on the dial and TLS handshake
//     so a single stuck phase cannot consume the whole run budget; the target's
//     total timeout (the context deadline) remains the primary bound.
//   - GetClientCertificate rather than a fixed Certificates list: a client
//     certificate identifies Sentinel and is therefore a credential, so it must
//     obey the same origin guard as headers and auth. The callback is consulted
//     per handshake and returns the identity only for the target's own origin.
//   - ServerName and MaxVersion are connection-wide (the transport shares one
//     tls.Config across hops and mutating it per hop would race the dial
//     goroutine). MaxVersion is only ever more restrictive, so that is harmless;
//     for ServerName see the note on Options.TLSServerName.
func newTransport(cfg transportConfig) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   safetyDialTimeout,
		KeepAlive: -1, // no TCP keep-alive
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   safetyTLSTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify:   true, //nolint:gosec // verified in VerifyConnection during the handshake.
			VerifyConnection:     cfg.verify,
			GetClientCertificate: cfg.clientCertificate,
			ServerName:           cfg.serverName,
			MinVersion:           tls.VersionTLS12,
			MaxVersion:           cfg.maxVersion,
		},
	}
}

// transportConfig carries the per-target TLS wiring into newTransport.
type transportConfig struct {
	// verify inspects the peer certificate during the handshake and aborts it by
	// returning an error.
	verify func(tls.ConnectionState) error
	// clientCertificate supplies the client identity when the server asks for
	// one. It is always installed; the callback itself decides whether the
	// current hop may see the certificate.
	clientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	// serverName overrides SNI and is empty unless the target configured one.
	serverName string
	// maxVersion caps the highest offered TLS version; zero means Go's default.
	maxVersion uint16
}

// Secondary safety thresholds (not user-configurable). The per-target total
// timeout is the real bound; these only stop a single phase from hanging.
const (
	safetyDialTimeout = 30 * time.Second
	safetyTLSTimeout  = 15 * time.Second
)

// traceContext attaches the hop trace to the request context.
func traceContext(ctx context.Context, tr *hopTrace) context.Context {
	return httptrace.WithClientTrace(ctx, tr.clientTrace())
}

// hostname extracts the host (without port) from a URL for certificate hostname
// verification.
func hostname(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
