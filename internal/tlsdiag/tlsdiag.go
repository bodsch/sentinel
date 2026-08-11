// Package tlsdiag provides protocol-independent TLS diagnostics: it turns a
// completed handshake (a *tls.ConnectionState) into a typed Info value and
// classifies certificate problems into a probe.FailureReason.
//
// The package deliberately lives outside internal/probe/http even though HTTPS
// is its only caller today. TLS is not an HTTP concern — the exported metrics
// are named sentinel_tls_*, not sentinel_http_tls_* — and a future standalone
// tls: probe or a TLS-enabled TCP probe must be able to reuse the same
// inspection and the same metric series without duplicating either. Protocol
// packages attach an *Info to their diagnostics and implement Provider; the
// Collector here then emits every sentinel_tls_* series for them.
package tlsdiag

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"math"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// maxRecordedSANs caps how many subject alternative names are retained in Info.
// The full count is always reported via SANCount; only the retained list is
// bounded. Shared-hosting and CDN certificates routinely carry hundreds of SANs,
// and one Info is held in the result store per target for as long as the target
// exists, so an uncapped list would let a remote server dictate Sentinel's
// resident memory.
const maxRecordedSANs = 64

// Provider is implemented by protocol diagnostics that carry TLS information.
// Collector type-asserts against it, so a new protocol gains the complete
// sentinel_tls_* series by implementing this single method.
type Provider interface {
	// TLSDiagnostics returns the TLS information for the probed connection, or
	// nil when the probe did not use TLS.
	TLSDiagnostics() *Info
}

// Info is the full TLS diagnostic picture of one connection. It is populated by
// Inspect and is safe to share read-only across goroutines once returned (the
// collector reads it at scrape time while the prober may already be building the
// next one).
type Info struct {
	// --- leaf certificate validity ---

	// ExpiresAt is the leaf certificate's NotAfter.
	ExpiresAt time.Time
	// NotBefore is the leaf certificate's NotBefore. Together with ExpiresAt it
	// gives the validity window, which makes certificate rotation visible.
	NotBefore time.Time
	// RemainingDays is the whole days until the leaf expires; negative if it has
	// already expired.
	RemainingDays int
	// HostnameValid reports whether the leaf is valid for the probed host.
	HostnameValid bool
	// Valid reports whether the certificate passed every check: inside its
	// validity window, hostname matches, and the chain verified against the
	// configured roots. It stays honest under skipVerify.
	Valid bool
	// SelfSigned reports whether the leaf's issuer equals its subject.
	SelfSigned bool

	// --- chain ---

	// ChainLength is the number of certificates in the evaluated chain.
	ChainLength int
	// ChainVerified reports whether the chain verified against the roots.
	ChainVerified bool
	// ChainEarliestExpiry is the earliest NotAfter across the evaluated chain.
	// It is the value to alert on: an intermediate expiring before the leaf
	// breaks the connection just as surely, and is invisible in leaf-only
	// metrics.
	ChainEarliestExpiry time.Time
	// ChainEarliestRemainingDays is the whole days until ChainEarliestExpiry;
	// negative if already expired.
	ChainEarliestRemainingDays int

	// --- negotiated connection ---

	// Version is the negotiated TLS version (tls.VersionTLS12, ...).
	Version uint16
	// VersionName is the human-readable form, e.g. "TLS 1.3".
	VersionName string
	// CipherSuite is the negotiated cipher suite ID.
	CipherSuite uint16
	// CipherName is the human-readable suite name, e.g. "TLS_AES_128_GCM_SHA256".
	CipherName string
	// ALPN is the application protocol agreed via ALPN, e.g. "h2". It is empty
	// when the client offered none or the server selected none — which is the
	// normal case for the HTTP probe, whose transport does not negotiate ALPN.
	ALPN string

	// --- leaf metadata ---

	// SubjectCN is the leaf's subject common name.
	SubjectCN string
	// IssuerCN is the issuing CA's common name.
	IssuerCN string
	// Serial is the leaf's serial number in lowercase hexadecimal.
	Serial string
	// FingerprintSHA256 is the hex-encoded SHA-256 digest of the leaf's DER
	// encoding — the fingerprint browsers and openssl display.
	FingerprintSHA256 string
	// SignatureAlgorithm is the algorithm the leaf was signed with, e.g.
	// "SHA256-RSA". A lingering "SHA1-RSA" is a finding in itself.
	SignatureAlgorithm string
	// PublicKeyAlgorithm is the leaf's key algorithm, e.g. "ECDSA".
	PublicKeyAlgorithm string
	// KeyBits is the public key size in bits (RSA modulus length, EC curve size,
	// 256 for Ed25519); 0 when it cannot be determined.
	KeyBits int
	// SANs are the leaf's subject alternative names (DNS names first, then IP
	// addresses), truncated to maxRecordedSANs entries.
	SANs []string
	// SANCount is the untruncated number of subject alternative names.
	SANCount int

	// --- revocation ---

	// OCSP describes the stapled OCSP response; nil when the server stapled
	// none.
	OCSP *OCSPInfo
}

// Inspect validates and diagnoses the server certificate on a completed
// handshake.
//
// Callers dial with InsecureSkipVerify so the handshake never auto-fails; this
// function then performs verification itself. That is what lets Sentinel report
// certificate_expired distinctly from "unreachable", compute remaining days even
// for an already-expired certificate, and — unlike the standard client — still
// expose diagnostics when a certificate is rejected.
//
// Verification:
//   - expiry (NotBefore/NotAfter) and hostname are always checked;
//   - the certificate chain is verified against roots (nil = system roots),
//     unless skipVerify is set.
//
// skipVerify accepts any certificate: Info still reports the real validity (so
// sentinel_tls_certificate_valid stays honest), but the returned reason is
// ReasonNone so the probe does not fail. Use it only for endpoints whose
// certificate cannot be verified (e.g. self-signed internal targets).
//
// Parameters:
//   - state: the completed handshake state; nil or certificate-less state is a
//     TLS error.
//   - host: the hostname the certificate must be valid for.
//   - now: the reference time for every validity comparison (injectable for
//     deterministic tests).
//   - roots: the trust anchors; nil means the system roots.
//   - skipVerify: report but never fail on an unacceptable certificate.
//
// It returns the gathered Info (never nil when a leaf certificate is present)
// and a FailureReason: ReasonNone when the certificate is acceptable under the
// active policy.
func Inspect(state *tls.ConnectionState, host string, now time.Time, roots *x509.CertPool, skipVerify bool) (*Info, probe.FailureReason) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, probe.ReasonTLSError
	}
	leaf := state.PeerCertificates[0]

	info := &Info{
		ExpiresAt: leaf.NotAfter,
		NotBefore: leaf.NotBefore,
		// Floor (not truncate-toward-zero) so an already-expired certificate
		// yields a negative value even when it expired less than 24h ago.
		RemainingDays: wholeDaysUntil(leaf.NotAfter, now),
		SelfSigned:    bytes.Equal(leaf.RawIssuer, leaf.RawSubject),

		Version:     state.Version,
		VersionName: tls.VersionName(state.Version),
		CipherSuite: state.CipherSuite,
		CipherName:  tls.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
	}
	describeLeaf(info, leaf)

	expired := now.After(leaf.NotAfter)
	notYetValid := now.Before(leaf.NotBefore)
	info.HostnameValid = leaf.VerifyHostname(host) == nil

	// Chain trust: verify the leaf against the roots (nil => system roots) using
	// the presented intermediates. This runs even under skipVerify so the
	// Info.Valid diagnostic stays honest — skipVerify only affects whether an
	// untrusted result fails the probe, not what is reported.
	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	chains, chainErr := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	info.ChainVerified = chainErr == nil

	// Evaluate the chain a client would actually build: the shortest verified
	// one. When verification failed there is none, so fall back to the chain the
	// server presented — the diagnostics must stay useful precisely in the
	// failure case, which is when an operator looks at them.
	chain := shortestChain(chains)
	if chain == nil {
		chain = state.PeerCertificates
	}
	info.ChainLength = len(chain)
	// Take the earliest expiry across both the verified chain and everything the
	// server presented. Either set alone can miss a real outage: a certificate
	// the server sends but Go routes around (a superfluous cross-signed
	// intermediate) still breaks clients whose trust store needs it, and the
	// root that only appears in the verified chain breaks everyone when it
	// lapses. The union is the conservative answer, and it never warns later
	// than the presented-chain-only value the blackbox_exporter reports.
	info.ChainEarliestExpiry = earliestExpiry(chain, state.PeerCertificates)
	info.ChainEarliestRemainingDays = wholeDaysUntil(info.ChainEarliestExpiry, now)

	// The stapled response is signed by the leaf's issuer; pass it along so the
	// signature can be verified rather than trusted blindly.
	info.OCSP = inspectStaple(state.OCSPResponse, leaf, issuerOf(chain))

	info.Valid = !expired && !notYetValid && info.HostnameValid && info.ChainVerified

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
	case !info.ChainVerified:
		// Untrusted / unknown-CA (e.g. a self-signed cert or a MITM): fail unless
		// the operator opted out via insecure_skip_verify or provided a ca_file.
		return info, probe.ReasonCertificateInvalid
	}
	return info, probe.ReasonNone
}

// shortestChain returns the shortest of the verified chains, which is the one a
// client would follow. It returns nil when there are none.
func shortestChain(chains [][]*x509.Certificate) []*x509.Certificate {
	var best []*x509.Certificate
	for _, c := range chains {
		if len(c) == 0 {
			continue
		}
		if best == nil || len(c) < len(best) {
			best = c
		}
	}
	return best
}

// earliestExpiry returns the earliest NotAfter across every given certificate
// set. Sets may overlap; duplicates do not change the minimum. It returns the
// zero time when no certificate was supplied.
func earliestExpiry(sets ...[]*x509.Certificate) time.Time {
	var earliest time.Time
	for _, set := range sets {
		for _, c := range set {
			if earliest.IsZero() || c.NotAfter.Before(earliest) {
				earliest = c.NotAfter
			}
		}
	}
	return earliest
}

// issuerOf returns the certificate that issued the chain's leaf, or nil when the
// chain carries no issuer (a bare leaf, or a self-signed certificate presented
// alone).
func issuerOf(chain []*x509.Certificate) *x509.Certificate {
	if len(chain) < 2 {
		return nil
	}
	return chain[1]
}

// wholeDaysUntil returns the whole days from now until t, flooring so an elapsed
// deadline yields a negative value even when it passed less than 24h ago. A zero
// t (no data) yields 0.
func wholeDaysUntil(t, now time.Time) int {
	if t.IsZero() {
		return 0
	}
	return int(math.Floor(t.Sub(now).Hours() / 24))
}
