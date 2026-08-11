package tlsdiag

import (
	"crypto/x509"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSP status values reported by Info.OCSP.Status. They mirror the RFC 6960
// certificate statuses, plus StatusInvalid for a response that was stapled but
// could not be trusted.
const (
	// StatusGood means the CA confirms the certificate is not revoked.
	StatusGood = "good"
	// StatusRevoked means the CA has revoked the certificate.
	StatusRevoked = "revoked"
	// StatusUnknown means the responder does not know about the certificate.
	StatusUnknown = "unknown"
	// StatusInvalid means a response was stapled but could not be parsed, was
	// not signed by the certificate's issuer, or referred to a different
	// certificate. It is deliberately distinct from "unknown": the responder
	// said nothing meaningful because the staple itself is broken.
	StatusInvalid = "invalid"
)

// OCSPInfo describes the OCSP response the server stapled to the handshake.
//
// Sentinel evaluates only the stapled response and never contacts an OCSP
// responder itself. That keeps a probe to exactly one network conversation:
// an extra responder request would add its latency to the measurement, make a
// responder outage look like a target failure, and disclose the monitored host
// list to the CA.
type OCSPInfo struct {
	// Status is one of StatusGood, StatusRevoked, StatusUnknown or
	// StatusInvalid.
	Status string
	// ProducedAt is when the responder generated the response.
	ProducedAt time.Time
	// ThisUpdate is when the reported status was known to be correct.
	ThisUpdate time.Time
	// NextUpdate is when newer status information will be available. A staple
	// past this point is stale and browsers may reject it; it is zero when the
	// responder did not set it.
	NextUpdate time.Time
	// RevokedAt is when the certificate was revoked; zero unless Status is
	// StatusRevoked.
	RevokedAt time.Time
	// Error describes why the staple could not be trusted; empty unless Status
	// is StatusInvalid.
	Error string
}

// Good reports whether the responder positively confirmed the certificate is not
// revoked.
func (o *OCSPInfo) Good() bool { return o != nil && o.Status == StatusGood }

// inspectStaple parses the OCSP response the server stapled to the handshake.
//
// The response is verified rather than trusted: it must be signed by the
// certificate's issuer and must refer to that very certificate. A staple that
// fails either check is reported as StatusInvalid instead of being silently
// dropped — a broken staple is itself a finding.
//
// Parameters:
//   - der: the raw stapled response; empty when the server stapled none.
//   - leaf: the certificate the response must refer to.
//   - issuer: the leaf's issuer, used to verify the response signature. When it
//     is nil (no chain was available) the signature cannot be checked and the
//     staple is reported as invalid.
//
// It returns nil when nothing was stapled, so callers can distinguish "no
// staple" from "a staple that says something".
func inspectStaple(der []byte, leaf, issuer *x509.Certificate) *OCSPInfo {
	if len(der) == 0 {
		return nil
	}
	if issuer == nil {
		return &OCSPInfo{
			Status: StatusInvalid,
			Error:  "no issuer certificate available to verify the stapled response",
		}
	}

	resp, err := ocsp.ParseResponseForCert(der, leaf, issuer)
	if err != nil {
		return &OCSPInfo{Status: StatusInvalid, Error: err.Error()}
	}

	info := &OCSPInfo{
		ProducedAt: resp.ProducedAt,
		ThisUpdate: resp.ThisUpdate,
		NextUpdate: resp.NextUpdate,
	}
	switch resp.Status {
	case ocsp.Good:
		info.Status = StatusGood
	case ocsp.Revoked:
		info.Status = StatusRevoked
		info.RevokedAt = resp.RevokedAt
	default:
		info.Status = StatusUnknown
	}
	return info
}
