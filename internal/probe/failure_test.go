package probe

import "testing"

func TestFailureReasonValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		reason FailureReason
		want   bool
	}{
		{"none is not a valid failure", ReasonNone, false},
		{"dns_error", ReasonDNSError, true},
		{"connection_refused", ReasonConnectionRefused, true},
		{"certificate_invalid", ReasonCertificateInvalid, true},
		{"downgrade", ReasonDowngrade, true},
		{"timeout", ReasonTimeout, true},
		{"unknown value", FailureReason("bogus"), false},
		{"empty-like unknown", FailureReason(" "), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.reason.Valid(); got != tc.want {
				t.Fatalf("FailureReason(%q).Valid() = %v, want %v", tc.reason, got, tc.want)
			}
		})
	}
}

// TestAllReasonsValid guards against a constant being added without a matching
// entry in the allReasons set (or vice versa).
func TestAllReasonsValid(t *testing.T) {
	t.Parallel()

	declared := []FailureReason{
		ReasonDNSError, ReasonTCPTimeout, ReasonConnectionRefused, ReasonTLSError,
		ReasonCertificateExpired, ReasonCertificateInvalid, ReasonRedirectLoop,
		ReasonRedirectLimit, ReasonDowngrade, ReasonHTTPStatusError,
		ReasonValidationFailed, ReasonTimeout, ReasonNetworkError,
	}

	if len(declared) != len(allReasons) {
		t.Fatalf("declared reasons (%d) and allReasons set (%d) differ in size", len(declared), len(allReasons))
	}
	for _, r := range declared {
		if !r.Valid() {
			t.Errorf("declared reason %q missing from allReasons", r)
		}
	}
}
