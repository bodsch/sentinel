package dns

// Diagnostics is the DNS-specific detail attached to a probe.Result. It
// implements probe.Diagnostics via ProbeType.
type Diagnostics struct {
	// ResponseCode is the DNS RCODE of the response (0 == NOERROR).
	ResponseCode int
	// ResponseCodeText is the human-readable RCODE (e.g. "NOERROR", "NXDOMAIN").
	ResponseCodeText string
	// AnswerCount is the number of answer records of the queried type.
	AnswerCount int
	// Answers are the answer values (IPs for A/AAAA, exchange hosts for MX,
	// joined strings for TXT), with trailing dots trimmed.
	Answers []string
	// Truncated reports whether the UDP response was truncated (TC bit). When it
	// is, the probe retries over TCP, so a successful result carries the full
	// answer set and Truncated reflects the final response.
	Truncated bool
}

// ProbeType implements probe.Diagnostics.
func (*Diagnostics) ProbeType() string { return ProbeType }
