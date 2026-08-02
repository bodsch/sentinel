package http

import "time"

// Diagnostics is the HTTP-specific detail attached to a probe.Result. It
// implements probe.Diagnostics via ProbeType.
type Diagnostics struct {
	// FinalURL is the URL of the last hop (after following redirects).
	FinalURL string
	// StatusCode is the final response status code (0 if the request never
	// produced a response).
	StatusCode int
	// Redirects is the ordered chain of redirect hops that were followed. Each
	// step records the URL that returned the redirect and its status code.
	Redirects []RedirectStep
	// TLS holds certificate diagnostics for HTTPS targets; nil for plain HTTP
	// or when no TLS state was available.
	TLS *TLSInfo
}

// ProbeType implements probe.Diagnostics.
func (*Diagnostics) ProbeType() string { return ProbeType }

// RedirectStep is one hop in a redirect chain.
type RedirectStep struct {
	// URL is the address that returned the redirect.
	URL string
	// StatusCode is the redirect status (e.g. 301, 302).
	StatusCode int
}

// TLSInfo holds the certificate diagnostics gathered by manual inspection of the
// peer certificate.
type TLSInfo struct {
	// ExpiresAt is the leaf certificate's NotAfter.
	ExpiresAt time.Time
	// RemainingDays is the whole days until expiry; negative if already expired.
	RemainingDays int
	// HostnameValid reports whether the certificate is valid for the target host.
	HostnameValid bool
	// Valid reports whether the certificate passed all of Sentinel's 0.1 checks
	// (not expired, not yet-valid, hostname matches).
	Valid bool
}
