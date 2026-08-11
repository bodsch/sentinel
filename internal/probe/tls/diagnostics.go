package tls

import "bodsch.me/sentinel/internal/tlsdiag"

// Diagnostics is the TLS-probe-specific detail attached to a probe.Result. It
// implements probe.Diagnostics via ProbeType and tlsdiag.Provider via
// TLSDiagnostics — the latter is what makes the shared sentinel_tls_* collector
// emit the full certificate, chain and OCSP series for this probe without a line
// of collector code here.
type Diagnostics struct {
	// Endpoint is the "ip:port" that answered. With a multi-homed name it
	// identifies which backend the measurement describes.
	Endpoint string
	// ServerName is the name sent in the SNI extension and validated against the
	// certificate. It differs from the connect host when the target configured
	// server_name, and is empty when the host is an IP literal and no override
	// was given (Go sends no SNI for IP addresses).
	ServerName string
	// ALPN is the application protocol the server selected; empty when none was
	// offered or agreed.
	ALPN string
	// TLS holds the certificate diagnostics. It is nil only when the handshake
	// never completed.
	TLS *tlsdiag.Info
}

// ProbeType implements probe.Diagnostics.
func (*Diagnostics) ProbeType() string { return ProbeType }

// TLSDiagnostics implements tlsdiag.Provider. It tolerates a nil receiver so a
// typed-nil diagnostics value cannot panic the scrape.
func (d *Diagnostics) TLSDiagnostics() *tlsdiag.Info {
	if d == nil {
		return nil
	}
	return d.TLS
}
