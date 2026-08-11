package main

import (
	"crypto/tls"
	"testing"

	"bodsch.me/sentinel/internal/config"
	"bodsch.me/sentinel/internal/tlsdiag"
)

// TestTLSPolicyMapping covers the translation from configuration to prober
// policy, including the cases that must yield no policy at all so an untouched
// target keeps behaving exactly as before.
func TestTLSPolicyMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		expect *config.TLSExpect
		verify func(*testing.T, *tlsdiag.Policy)
	}{
		{
			name:   "no block",
			expect: nil,
			verify: func(t *testing.T, p *tlsdiag.Policy) {
				if p != nil {
					t.Errorf("policy = %+v, want nil", p)
				}
			},
		},
		{
			// An empty block enforces nothing; collapsing it to nil keeps the
			// prober's hot path free of a no-op evaluation.
			name:   "empty block",
			expect: &config.TLSExpect{},
			verify: func(t *testing.T, p *tlsdiag.Policy) {
				if p != nil {
					t.Errorf("policy = %+v, want nil for an empty block", p)
				}
			},
		},
		{
			name:   "whitespace-only values",
			expect: &config.TLSExpect{MinVersion: "  ", IssuerRegex: "  "},
			verify: func(t *testing.T, p *tlsdiag.Policy) {
				if p != nil {
					t.Errorf("policy = %+v, want nil", p)
				}
			},
		},
		{
			name: "all fields",
			expect: &config.TLSExpect{
				MinDaysRemaining:    21,
				MinVersion:          "1.3",
				RequireOCSPStapling: true,
				IssuerRegex:         `Let's Encrypt`,
			},
			verify: func(t *testing.T, p *tlsdiag.Policy) {
				if p == nil {
					t.Fatal("policy = nil, want a populated policy")
				}
				if p.MinDaysRemaining != 21 {
					t.Errorf("min days = %d, want 21", p.MinDaysRemaining)
				}
				if p.MinVersion != tls.VersionTLS13 {
					t.Errorf("min version = %#x, want TLS 1.3", p.MinVersion)
				}
				if !p.RequireOCSPStapling {
					t.Error("stapling requirement lost")
				}
				if p.IssuerRegex == nil || !p.IssuerRegex.MatchString("Let's Encrypt R3") {
					t.Errorf("issuer regex = %v, does not match the configured issuer", p.IssuerRegex)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			policy, err := tlsPolicy(tc.expect)
			if err != nil {
				t.Fatalf("tlsPolicy: %v", err)
			}
			tc.verify(t, policy)
		})
	}
}

// TestTLSPolicyRejectsInvalidValues is defensive: configuration validation
// already rejects these, so the mapping must not silently swallow them if it is
// ever reached another way.
func TestTLSPolicyRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	if _, err := tlsPolicy(&config.TLSExpect{MinVersion: "1.1"}); err == nil {
		t.Error("expected an error for an unsupported minimum version")
	}
	if _, err := tlsPolicy(&config.TLSExpect{IssuerRegex: "["}); err == nil {
		t.Error("expected an error for an invalid issuer regex")
	}
}
