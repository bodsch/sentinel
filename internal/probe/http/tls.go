package http

import (
	"crypto/tls"
	"math"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// inspectTLS performs manual certificate diagnostics on a completed handshake.
//
// The probe deliberately dials with InsecureSkipVerify so the handshake does not
// auto-fail on an expired or hostname-mismatched certificate; this function then
// classifies the leaf certificate itself. That is what lets Sentinel report
// certificate_expired distinctly from "unreachable", and compute remaining days
// even for an already-expired certificate.
//
// 0.1 scope: expiry (NotBefore/NotAfter) and hostname match. Full chain
// verification, OCSP and SAN detail are 0.2.
//
// It returns the gathered TLSInfo (never nil when a leaf certificate is present)
// and a FailureReason: ReasonNone when the certificate is acceptable.
func inspectTLS(state *tls.ConnectionState, host string, now time.Time) (*TLSInfo, probe.FailureReason) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, probe.ReasonTLSError
	}
	leaf := state.PeerCertificates[0]

	// Floor (not truncate-toward-zero) so an already-expired certificate yields
	// a negative value even when it expired less than 24h ago.
	info := &TLSInfo{
		ExpiresAt:     leaf.NotAfter,
		RemainingDays: int(math.Floor(leaf.NotAfter.Sub(now).Hours() / 24)),
	}

	switch {
	case now.After(leaf.NotAfter):
		return info, probe.ReasonCertificateExpired
	case now.Before(leaf.NotBefore):
		// Not yet valid — treat as an invalid certificate.
		return info, probe.ReasonCertificateInvalid
	}

	if err := leaf.VerifyHostname(host); err != nil {
		info.HostnameValid = false
		return info, probe.ReasonCertificateInvalid
	}
	info.HostnameValid = true
	info.Valid = true

	return info, probe.ReasonNone
}
