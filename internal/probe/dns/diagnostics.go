package dns

import (
	"time"

	dnslib "github.com/miekg/dns"

	"bodsch.me/sentinel/internal/probe"
)

// Diagnostics is the DNS-specific detail attached to a probe.Result. It
// implements probe.Diagnostics via ProbeType.
//
// The top-level fields describe the first configured resolver, so a
// single-resolver target looks exactly as before. With several resolvers,
// Resolvers carries one entry per resolver and Consistent the comparison.
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
	// Resolvers holds the per-resolver results in configured order. It is nil
	// for a single-resolver target.
	Resolvers []ResolverResult
	// Consistent reports whether all resolvers that answered returned the same
	// answer set — or, for the authoritative check, whether all nameservers
	// returned the same SOA serial. True when there is nothing to compare.
	Consistent bool
	// Nameservers holds the per-address results of the authoritative check,
	// sorted by host and address. Nil for an ordinary query. In that mode the
	// top-level fields describe the NS lookup: Answers are the nameserver
	// names.
	Nameservers []NameserverResult
}

// ResolverResult is the outcome of the query against one resolver.
type ResolverResult struct {
	// Server is the resolver as "host:port".
	Server string
	// Duration is the time this resolver took, including a TCP retry.
	Duration time.Duration
	// Reason is ReasonNone for a NOERROR response, otherwise why the query
	// against this resolver failed.
	Reason probe.FailureReason
	// ResponseCode and ResponseCodeText are the RCODE; zero/empty when the
	// resolver produced no response.
	ResponseCode     int
	ResponseCodeText string
	// Answers are the answer values, as in Diagnostics.Answers.
	Answers []string
	// Truncated reports a truncated final response.
	Truncated bool

	// err is the transport error when the resolver produced no response.
	err error
	// msg is the response, for callers that need more than the answers.
	msg *dnslib.Msg
}

// ProbeType implements probe.Diagnostics.
func (*Diagnostics) ProbeType() string { return ProbeType }
