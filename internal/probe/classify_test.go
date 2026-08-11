package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
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
