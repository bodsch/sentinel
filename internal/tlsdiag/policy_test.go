package tlsdiag

import (
	"crypto/tls"
	"regexp"
	"testing"

	"bodsch.me/sentinel/internal/probe"
)

// soundInfo is a connection that satisfies every policy a test does not
// deliberately break.
func soundInfo() *Info {
	return &Info{
		RemainingDays:              90,
		ChainEarliestRemainingDays: 90,
		Version:                    tls.VersionTLS13,
		VersionName:                "TLS 1.3",
		IssuerCN:                   "Let's Encrypt R3",
		OCSP:                       &OCSPInfo{Status: StatusGood},
	}
}

func TestPolicyEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		policy *Policy
		want   bool
	}{
		{"nil", nil, true},
		{"zero value", &Policy{}, true},
		{"days set", &Policy{MinDaysRemaining: 1}, false},
		{"version set", &Policy{MinVersion: tls.VersionTLS13}, false},
		{"stapling required", &Policy{RequireOCSPStapling: true}, false},
		{"issuer set", &Policy{IssuerRegex: regexp.MustCompile("x")}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.policy.Empty(); got != tc.want {
				t.Errorf("Empty() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPolicyEvaluateNoop asserts the default path stays inert: without a policy
// nothing new can ever fail a probe.
func TestPolicyEvaluateNoop(t *testing.T) {
	t.Parallel()

	if got := (*Policy)(nil).Evaluate(soundInfo()); got != probe.ReasonNone {
		t.Errorf("nil policy returned %q, want none", got)
	}
	if got := (&Policy{MinDaysRemaining: 30}).Evaluate(nil); got != probe.ReasonNone {
		t.Errorf("policy on a non-TLS connection returned %q, want none", got)
	}
}

func TestPolicyEvaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		policy Policy
		mutate func(*Info)
		want   probe.FailureReason
	}{
		{
			name:   "satisfied",
			policy: Policy{MinDaysRemaining: 30, MinVersion: tls.VersionTLS13, RequireOCSPStapling: true, IssuerRegex: regexp.MustCompile(`Let's Encrypt`)},
			want:   probe.ReasonNone,
		},
		{
			name:   "leaf inside the renewal window",
			policy: Policy{MinDaysRemaining: 30},
			mutate: func(i *Info) { i.RemainingDays = 29; i.ChainEarliestRemainingDays = 29 },
			want:   probe.ReasonCertificateExpiring,
		},
		{
			name:   "exactly at the threshold is fine",
			policy: Policy{MinDaysRemaining: 30},
			mutate: func(i *Info) { i.RemainingDays = 30; i.ChainEarliestRemainingDays = 30 },
			want:   probe.ReasonNone,
		},
		{
			// The case leaf-only metrics miss entirely.
			name:   "intermediate inside the renewal window",
			policy: Policy{MinDaysRemaining: 30},
			mutate: func(i *Info) { i.RemainingDays = 300; i.ChainEarliestRemainingDays = 5 },
			want:   probe.ReasonCertificateExpiring,
		},
		{
			name:   "version below the minimum",
			policy: Policy{MinVersion: tls.VersionTLS13},
			mutate: func(i *Info) { i.Version = tls.VersionTLS12 },
			want:   probe.ReasonTLSPolicyViolation,
		},
		{
			name:   "version at the minimum",
			policy: Policy{MinVersion: tls.VersionTLS12},
			mutate: func(i *Info) { i.Version = tls.VersionTLS12 },
			want:   probe.ReasonNone,
		},
		{
			name:   "no staple",
			policy: Policy{RequireOCSPStapling: true},
			mutate: func(i *Info) { i.OCSP = nil },
			want:   probe.ReasonTLSPolicyViolation,
		},
		{
			name:   "revoked staple",
			policy: Policy{RequireOCSPStapling: true},
			mutate: func(i *Info) { i.OCSP = &OCSPInfo{Status: StatusRevoked} },
			want:   probe.ReasonTLSPolicyViolation,
		},
		{
			name:   "broken staple",
			policy: Policy{RequireOCSPStapling: true},
			mutate: func(i *Info) { i.OCSP = &OCSPInfo{Status: StatusInvalid, Error: "boom"} },
			want:   probe.ReasonTLSPolicyViolation,
		},
		{
			name:   "unexpected issuer",
			policy: Policy{IssuerRegex: regexp.MustCompile(`^DigiCert`)},
			want:   probe.ReasonTLSPolicyViolation,
		},
		{
			// Expiry outranks the other checks: it is the finding that needs
			// action soonest, so it must not be masked by a second breach.
			name:   "expiry wins over a version breach",
			policy: Policy{MinDaysRemaining: 30, MinVersion: tls.VersionTLS13},
			mutate: func(i *Info) { i.ChainEarliestRemainingDays = 1; i.Version = tls.VersionTLS12 },
			want:   probe.ReasonCertificateExpiring,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			info := soundInfo()
			if tc.mutate != nil {
				tc.mutate(info)
			}
			if got := tc.policy.Evaluate(info); got != tc.want {
				t.Errorf("Evaluate() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    uint16
		wantErr bool
	}{
		{in: "1.2", want: tls.VersionTLS12},
		{in: "1.3", want: tls.VersionTLS13},
		// Below the transport's own floor: accepting it would be a no-op the
		// operator could mistake for a guarantee.
		{in: "1.1", wantErr: true},
		{in: "1.0", wantErr: true},
		{in: "TLS1.3", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := ParseVersion(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseVersion(%q) = %#x, want an error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVersion(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseVersion(%q) = %#x, want %#x", tc.in, got, tc.want)
			}
		})
	}
}
