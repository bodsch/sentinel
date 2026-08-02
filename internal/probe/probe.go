// Package probe defines the protocol-agnostic contract every Sentinel probe
// implements, together with the typed result model those probes return.
//
// The design intentionally avoids an untyped metric bag (a former draft used
// map[string]float64). A typed Result gives compile-time safety and lets rich,
// protocol-specific diagnostics live in properly typed fields. Protocol packages
// (e.g. internal/probe/http) provide their own Prober implementation and their
// own Diagnostics value.
package probe

import (
	"context"
	"time"
)

// Prober executes a single monitoring check for one target.
//
// Implementations must:
//   - honour ctx cancellation and the deadline it carries (the caller sets the
//     total per-run timeout);
//   - never return an error — a failed check is a normal, successful execution
//     that yields a Result with Success == false and a classified FailureReason.
//
// Returning a Result rather than an error keeps "the target is down" (expected,
// measured) distinct from "the prober itself malfunctioned" (a bug).
type Prober interface {
	// Probe runs the check and returns its typed result. It blocks until the
	// check completes, ctx is done, or the deadline fires.
	Probe(ctx context.Context) Result

	// Type reports the probe's protocol identifier (e.g. "http"). It is used
	// as the value of the "type" metric label and in structured logs.
	Type() string
}

// Result is the normalised outcome of a single probe execution, shared by all
// protocols. Protocol-specific detail is carried in Diagnostics.
type Result struct {
	// Success reports whether the check passed all of its expectations.
	Success bool

	// FailureReason classifies why the check failed. It is the zero value
	// (ReasonNone) when Success is true.
	FailureReason FailureReason

	// Duration is the total wall-clock time of the run, including every
	// redirect hop for protocols that follow redirects.
	Duration time.Duration

	// Timings holds the per-phase breakdown. For protocols or phases that do
	// not apply, the corresponding fields stay zero.
	Timings Timings

	// Diagnostics carries protocol-specific detail (for example an HTTP
	// redirect chain or TLS certificate information). It may be nil.
	Diagnostics Diagnostics

	// Timestamp is when the run completed.
	Timestamp time.Time
}

// Timings is the phase-by-phase latency breakdown of a probe. Each field is the
// duration of that phase alone. For protocols that follow redirects, the network
// phases describe the final hop, while Result.Duration covers all hops.
type Timings struct {
	DNS      time.Duration // name resolution
	Connect  time.Duration // TCP connection establishment
	TLS      time.Duration // TLS handshake
	TTFB     time.Duration // time from request sent to first response byte
	Download time.Duration // reading the response body
}

// Diagnostics is protocol-specific diagnostic detail attached to a Result.
// Concrete types (e.g. HTTP diagnostics carrying the redirect chain and TLS
// info) implement it in their own protocol package. A consumer that needs the
// detail type-asserts to the concrete type; the metrics layer does not, because
// each protocol ships its own collector that knows its own diagnostics type.
type Diagnostics interface {
	// ProbeType reports the protocol these diagnostics describe (e.g. "http").
	// It doubles as the marker that makes a type a Diagnostics.
	ProbeType() string
}
