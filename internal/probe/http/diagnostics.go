package http

import (
	"bodsch.me/sentinel/internal/tlsdiag"
)

// Diagnostics is the HTTP-specific detail attached to a probe.Result. It
// implements probe.Diagnostics via ProbeType and tlsdiag.Provider via
// TLSDiagnostics.
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
	// or when no TLS state was available. It describes the final hop.
	TLS *tlsdiag.Info
}

// ProbeType implements probe.Diagnostics.
func (*Diagnostics) ProbeType() string { return ProbeType }

// TLSDiagnostics implements tlsdiag.Provider, which is what makes the shared
// sentinel_tls_* collector pick up HTTPS targets. It tolerates a nil receiver so
// a typed-nil diagnostics value cannot panic the scrape.
func (d *Diagnostics) TLSDiagnostics() *tlsdiag.Info {
	if d == nil {
		return nil
	}
	return d.TLS
}

// RedirectStep is one hop in a redirect chain.
type RedirectStep struct {
	// URL is the address that returned the redirect.
	URL string
	// StatusCode is the redirect status (e.g. 301, 302).
	StatusCode int
}
