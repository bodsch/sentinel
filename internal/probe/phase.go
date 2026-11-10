package probe

// Phase names a stage of a probe run. It tells an operator where a timed-out
// probe was stuck — "slow to resolve" and "never got a response" call for
// entirely different investigations, and a bare failure_reason=timeout cannot
// tell them apart.
//
// The set is closed and shared by all protocols so a log query for
// phase="connect" means the same thing for HTTP, TLS and TCP. The names match the
// phase timing metrics (sentinel_http_dns_duration_seconds, …).
type Phase string

// Phases of a probe run. The zero value, PhaseNone, means "not recorded".
const (
	PhaseNone Phase = ""

	// PhaseDNS is name resolution (for the DNS probe: the whole query).
	PhaseDNS Phase = "dns"
	// PhaseConnect is TCP connection establishment.
	PhaseConnect Phase = "connect"
	// PhaseTLS is the TLS handshake.
	PhaseTLS Phase = "tls"
	// PhaseTTFB is waiting for the first response byte after the request was
	// sent on an established connection.
	PhaseTTFB Phase = "ttfb"
	// PhaseDownload is reading the response body.
	PhaseDownload Phase = "download"
	// PhaseBanner is waiting for a TCP server's greeting banner.
	PhaseBanner Phase = "banner"
	// PhaseStartTLS is the plaintext dialogue that upgrades a connection to TLS
	// (greeting, capability check, the STARTTLS command).
	PhaseStartTLS Phase = "starttls"
)

// String returns the phase as a plain string for use in logs.
func (p Phase) String() string { return string(p) }

// IsTimeout reports whether r is one of the timeout reasons — the probe's total
// deadline (timeout) or a network-level timeout (tcp_timeout). Only these carry
// a TimeoutPhase; for every other reason the failure itself says where it
// happened.
func (r FailureReason) IsTimeout() bool {
	return r == ReasonTimeout || r == ReasonTCPTimeout
}
