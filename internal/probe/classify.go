package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"syscall"
)

// ClassifyNetworkError maps a transport-level error to a stable FailureReason.
// It inspects wrapped errors with errors.As/errors.Is, so it works regardless of
// how deeply the standard library nests the cause.
//
// It lives here rather than in a protocol package because every probe that opens
// a socket needs the same mapping, and three private copies would inevitably
// drift — a target would then report a different reason for the identical
// failure depending on which protocol observed it, which defeats the point of a
// closed reason set.
//
// Order matters: more specific causes are checked first. Anything unrecognised
// falls back to ReasonNetworkError rather than being silently misclassified.
//
// Parameters:
//   - err: the error to classify; nil yields ReasonNone.
//
// It returns the matching FailureReason.
func ClassifyNetworkError(err error) FailureReason {
	if err == nil {
		return ReasonNone
	}

	// Our own total timeout (or a parent cancellation, e.g. shutdown).
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ReasonTimeout
	}

	// DNS resolution failure.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return ReasonDNSError
	}

	// Connection refused / reset by peer.
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) {
		return ReasonConnectionRefused
	}

	// TLS-level failures. Probes that inspect certificates themselves dial with
	// InsecureSkipVerify, so expiry and hostname problems do not surface here
	// (they are classified from the inspection). Protocol-level TLS errors — for
	// example speaking TLS to a plaintext port — still do.
	// An alert from the peer is also a TLS-level failure: no shared protocol
	// version or cipher suite, and the "bad certificate" a server sends when it
	// rejects our client certificate, which under TLS 1.3 only arrives after the
	// handshake reports success.
	var alertErr tls.AlertError
	var recordErr tls.RecordHeaderError
	var certErr x509.CertificateInvalidError
	var hostErr x509.HostnameError
	var authErr x509.UnknownAuthorityError
	if isRemoteAlert(err) || errors.As(err, &alertErr) || errors.As(err, &recordErr) ||
		errors.As(err, &certErr) || errors.As(err, &hostErr) || errors.As(err, &authErr) {
		return ReasonTLSError
	}

	// A timeout that is not our context deadline (e.g. a dial timeout).
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReasonTCPTimeout
	}

	// Host/network unreachable — treat as a connection-establishment failure.
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return ReasonConnectionRefused
	}

	return ReasonNetworkError
}

// ClassifyHandshakeError maps an error returned by a TLS handshake to a stable
// FailureReason.
//
// It applies ClassifyNetworkError first, so timeouts, resets and alerts keep
// their usual reasons. What that leaves unrecognised is reported as
// ReasonTLSError instead of ReasonNetworkError: the TCP connection was already
// established, so a failure the handshake reports on its own — crypto/tls
// rejects a server that picks a protocol version or cipher suite it did not
// offer with a plain error, and a server that hangs up on the ClientHello
// yields end-of-file — is a TLS problem, not a network one.
//
// Parameters:
//   - err: the handshake error; nil yields ReasonNone.
//
// It returns the matching FailureReason.
func ClassifyHandshakeError(err error) FailureReason {
	reason := ClassifyNetworkError(err)
	if reason == ReasonNetworkError {
		return ReasonTLSError
	}
	return reason
}

// remoteErrorOp is the net.OpError operation crypto/tls uses for an alert
// received from the peer. The alert itself has an unexported type — the
// exported tls.AlertError is only returned by QUIC connections — so the
// operation name is the only way to recognise it.
const remoteErrorOp = "remote error"

// isRemoteAlert reports whether err carries a TLS alert sent by the peer.
func isRemoteAlert(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == remoteErrorOp
}
