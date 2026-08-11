package tlsdiag

import (
	"crypto/tls"
	"fmt"
	"regexp"

	"bodsch.me/sentinel/internal/probe"
)

// Policy is the operator's opt-in set of TLS expectations for one target. The
// zero Policy (and a nil *Policy) enforces nothing, so a target without a
// tls.expect block behaves exactly as it did before policies existed.
//
// Policies are evaluated *after* the handshake succeeded and after the response
// validators ran — they describe a connection that is cryptographically sound
// but does not meet an operational requirement. The security-critical checks
// (untrusted chain, expired certificate, hostname mismatch) stay in Inspect and
// still abort the handshake before any request is sent.
type Policy struct {
	// MinDaysRemaining is the minimum number of whole days the certificate must
	// remain valid. The check covers the whole chain, so an intermediate
	// expiring sooner than the leaf trips it too. Zero disables the check.
	MinDaysRemaining int
	// MinVersion is the lowest acceptable negotiated TLS version (a
	// tls.VersionTLS* constant). Zero disables the check.
	MinVersion uint16
	// RequireOCSPStapling demands that the server staple an OCSP response and
	// that the response says "good". A missing, broken, unknown or revoked
	// staple is a violation.
	RequireOCSPStapling bool
	// IssuerRegex, when set, must match the leaf's issuer common name. It pins
	// the issuing CA, which surfaces an unannounced CA migration — and a
	// certificate swapped by anyone able to obtain one from a different public
	// CA. Nil disables the check.
	IssuerRegex *regexp.Regexp
}

// Empty reports whether the policy enforces nothing.
func (p *Policy) Empty() bool {
	return p == nil || (p.MinDaysRemaining == 0 &&
		p.MinVersion == 0 &&
		!p.RequireOCSPStapling &&
		p.IssuerRegex == nil)
}

// Evaluate checks info against the policy.
//
// Parameters:
//   - info: the diagnostics of the completed handshake; nil means no TLS took
//     place, in which case there is nothing to enforce.
//
// It returns ReasonCertificateExpiring when the certificate is inside its
// renewal window, ReasonTLSPolicyViolation for every other breach, and
// ReasonNone when the connection satisfies the policy. Expiry is checked first
// because it is the finding that needs action soonest.
func (p *Policy) Evaluate(info *Info) probe.FailureReason {
	if p.Empty() || info == nil {
		return probe.ReasonNone
	}

	if p.MinDaysRemaining > 0 {
		// The chain value already includes the leaf, but comparing both keeps
		// the intent explicit and survives a future change to how the chain is
		// selected.
		remaining := min(info.RemainingDays, info.ChainEarliestRemainingDays)
		if remaining < p.MinDaysRemaining {
			return probe.ReasonCertificateExpiring
		}
	}

	if p.MinVersion != 0 && info.Version < p.MinVersion {
		return probe.ReasonTLSPolicyViolation
	}

	if p.RequireOCSPStapling && !info.OCSP.Good() {
		return probe.ReasonTLSPolicyViolation
	}

	if p.IssuerRegex != nil && !p.IssuerRegex.MatchString(info.IssuerCN) {
		return probe.ReasonTLSPolicyViolation
	}

	return probe.ReasonNone
}

// ParseVersion maps a configuration string to a TLS version constant.
//
// Only 1.2 and 1.3 are accepted: the probe transport sets MinVersion to TLS 1.2,
// so a lower bound below that could never be violated and would be a misleading
// no-op in a configuration file.
//
// Parameters:
//   - s: the version as written in the configuration, e.g. "1.3".
//
// It returns the tls.VersionTLS* constant, or an error describing the accepted
// values.
func ParseVersion(s string) (uint16, error) {
	switch s {
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version %q (supported: 1.2, 1.3)", s)
	}
}
