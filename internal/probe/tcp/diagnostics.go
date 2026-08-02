package tcp

// Diagnostics is the TCP-specific detail attached to a probe.Result. It
// implements probe.Diagnostics via ProbeType.
type Diagnostics struct {
	// Banner is the bytes read from the server after connecting. It is empty when
	// no banner validation was configured, or when the server sent nothing.
	Banner string
}

// ProbeType implements probe.Diagnostics.
func (*Diagnostics) ProbeType() string { return ProbeType }
