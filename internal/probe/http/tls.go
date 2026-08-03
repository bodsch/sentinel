package http

import (
	"crypto/tls"
	"crypto/x509"
	"math"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// inspectTLS validates and diagnoses the server certificate on a completed
// handshake.
//
// The probe deliberately dials with InsecureSkipVerify so the handshake never
// auto-fails; this function then performs verification itself. That is what lets
// Sentinel report certificate_expired distinctly from "unreachable", compute
// remaining days even for an already-expired certificate, and — unlike the
// standard client — still expose diagnostics when a certificate is rejected.
//
// Verification:
//   - expiry (NotBefore/NotAfter) and hostname are always checked;
//   - the certificate chain is verified against roots (nil = system roots),
//     unless skipVerify is set.
//
// skipVerify accepts any certificate: TLSInfo still reports the real validity
// (so sentinel_tls_certificate_valid stays honest), but the returned reason is
// ReasonNone so the probe does not fail. Use it only for endpoints whose
// certificate cannot be verified (e.g. self-signed internal targets).
//
// It returns the gathered TLSInfo (never nil when a leaf certificate is present)
// and a FailureReason: ReasonNone when the certificate is acceptable under the
// active policy.
func inspectTLS(state *tls.ConnectionState, host string, now time.Time, roots *x509.CertPool, skipVerify bool) (*TLSInfo, probe.FailureReason) {
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

	expired := now.After(leaf.NotAfter)
	notYetValid := now.Before(leaf.NotBefore)
	info.HostnameValid = leaf.VerifyHostname(host) == nil

	// Chain trust: verify the leaf against the roots (nil => system roots) using
	// the presented intermediates. This runs even under skipVerify so the
	// TLSInfo.Valid diagnostic stays honest — skipVerify only affects whether an
	// untrusted result fails the probe, not what is reported.
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	_, chainErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	chainTrusted := chainErr == nil

	info.Valid = !expired && !notYetValid && info.HostnameValid && chainTrusted

	// When accepting any certificate, record diagnostics but never fail.
	if skipVerify {
		return info, probe.ReasonNone
	}

	switch {
	case expired:
		return info, probe.ReasonCertificateExpired
	case notYetValid:
		return info, probe.ReasonCertificateInvalid
	case !info.HostnameValid:
		return info, probe.ReasonCertificateInvalid
	case !chainTrusted:
		// Untrusted / unknown-CA (e.g. a self-signed cert or a MITM): fail unless
		// the operator opted out via insecure_skip_verify or provided a ca_file.
		return info, probe.ReasonCertificateInvalid
	}
	return info, probe.ReasonNone
}
