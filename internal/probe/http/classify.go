package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"syscall"

	"bodsch.me/sentinel/internal/probe"
)

// classifyError maps a transport/request error to a stable FailureReason. It
// inspects wrapped errors with errors.As/errors.Is so it works regardless of how
// deeply net/http nests the cause.
//
// Order matters: more specific causes are checked first. Anything unrecognised
// falls back to ReasonNetworkError rather than being silently misclassified.
func classifyError(err error) probe.FailureReason {
	if err == nil {
		return probe.ReasonNone
	}

	// Our own total timeout (or a parent cancellation, e.g. shutdown).
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return probe.ReasonTimeout
	}

	// DNS resolution failure.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return probe.ReasonDNSError
	}

	// Connection refused / reset by peer.
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return probe.ReasonConnectionRefused
	}

	// TLS-level failures. With InsecureSkipVerify the handshake does not fail on
	// expiry/hostname (those are inspected manually), but protocol-level TLS
	// errors — e.g. speaking TLS to a plaintext port — still surface here.
	var recordErr tls.RecordHeaderError
	var certErr x509.CertificateInvalidError
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &recordErr) || errors.As(err, &certErr) ||
		errors.As(err, &hostErr) || errors.As(err, &authErr) {
		return probe.ReasonTLSError
	}

	// A timeout that is not our context deadline (e.g. a dial timeout).
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return probe.ReasonTCPTimeout
	}

	// Host/network unreachable — treat as a connection-establishment failure.
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return probe.ReasonConnectionRefused
	}

	return probe.ReasonNetworkError
}
