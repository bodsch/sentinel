package probe

// FailureReason is a stable, closed classification of why a probe failed. It is
// used as a metric label value, in structured logs, and for alerting, so the set
// of values is deliberately fixed rather than free-form text.
//
// The zero value, ReasonNone, means "no failure" and is what a successful
// Result carries.
type FailureReason string

// The 0.1 set of failure reasons. New reasons may be added in later versions;
// existing values must remain stable.
const (
	ReasonNone FailureReason = "" // no failure (successful probe)

	ReasonDNSError           FailureReason = "dns_error"
	ReasonTCPTimeout         FailureReason = "tcp_timeout"
	ReasonConnectionRefused  FailureReason = "connection_refused"
	ReasonTLSError           FailureReason = "tls_error"
	ReasonCertificateExpired FailureReason = "certificate_expired"
	ReasonCertificateInvalid FailureReason = "certificate_invalid" // e.g. hostname mismatch
	ReasonRedirectLoop       FailureReason = "redirect_loop"
	ReasonRedirectLimit      FailureReason = "redirect_limit_exceeded"
	ReasonDowngrade          FailureReason = "downgrade" // HTTPS -> HTTP redirect
	ReasonHTTPStatusError    FailureReason = "http_status_error"
	ReasonValidationFailed   FailureReason = "validation_failed"
	ReasonTimeout            FailureReason = "timeout"

	// ReasonCertificateExpiring means the certificate is still valid but expires
	// within the window the target declared via tls.expect.min_days_remaining.
	// It is deliberately distinct from ReasonCertificateExpired: the service
	// still works, and the response is to renew, not to page.
	ReasonCertificateExpiring FailureReason = "certificate_expiring"

	// ReasonTLSPolicyViolation means the connection was cryptographically sound
	// but breached a policy the target declared via tls.expect (minimum TLS
	// version, required OCSP stapling, expected issuer).
	ReasonTLSPolicyViolation FailureReason = "tls_policy_violation"

	// ReasonNetworkError is the catch-all for network-level failures that do
	// not fit a more specific reason above. It exists so the probe never has to
	// silently misclassify an unusual error.
	ReasonNetworkError FailureReason = "network_error"
)

// allReasons is the set of valid, non-empty failure reasons, used by Valid.
var allReasons = map[FailureReason]struct{}{
	ReasonDNSError:            {},
	ReasonTCPTimeout:          {},
	ReasonConnectionRefused:   {},
	ReasonTLSError:            {},
	ReasonCertificateExpired:  {},
	ReasonCertificateInvalid:  {},
	ReasonCertificateExpiring: {},
	ReasonTLSPolicyViolation:  {},
	ReasonRedirectLoop:        {},
	ReasonRedirectLimit:       {},
	ReasonDowngrade:           {},
	ReasonHTTPStatusError:     {},
	ReasonValidationFailed:    {},
	ReasonTimeout:             {},
	ReasonNetworkError:        {},
}

// Valid reports whether r is a recognised failure reason. ReasonNone is not
// considered a valid *failure* reason and returns false.
func (r FailureReason) Valid() bool {
	_, ok := allReasons[r]
	return ok
}

// String returns the reason as a plain string for use in labels and logs.
func (r FailureReason) String() string {
	return string(r)
}
