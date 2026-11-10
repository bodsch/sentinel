package dns

import (
	"time"

	dnslib "github.com/miekg/dns"
)

// earliestSignatureExpiry returns the earliest expiration among the RRSIGs in
// the answer section that cover qtype, or the zero time when there are none.
//
// Only the signatures over the queried type count: a CNAME chain carries
// signatures of other types whose expiry says nothing about the record asked
// for.
//
// Parameters:
//   - resp: the response.
//   - qtype: the queried record type.
func earliestSignatureExpiry(resp *dnslib.Msg, qtype uint16) time.Time {
	var earliest time.Time
	for _, rr := range resp.Answer {
		sig, ok := rr.(*dnslib.RRSIG)
		if !ok || sig.TypeCovered != qtype {
			continue
		}
		// RRSIG times are seconds since the epoch modulo 2^32 (RFC 4034
		// section 3.1.5); read as unsigned they are correct until 2106.
		exp := time.Unix(int64(sig.Expiration), 0)
		if earliest.IsZero() || exp.Before(earliest) {
			earliest = exp
		}
	}
	return earliest
}

// dnssecSummary folds the per-resolver DNSSEC results into the target's
// verdict. A resolver without a response has nothing to vouch for and is
// reported through its own failure instead.
func dnssecSummary(results []ResolverResult) *DNSSECInfo {
	info := &DNSSECInfo{Validated: true}
	answered := false
	for _, r := range results {
		if r.err != nil {
			continue
		}
		answered = true
		if !r.Authenticated {
			info.Validated = false
		}
		if !r.SignatureExpiry.IsZero() && (info.SignatureExpiry.IsZero() || r.SignatureExpiry.Before(info.SignatureExpiry)) {
			info.SignatureExpiry = r.SignatureExpiry
		}
	}
	if !answered {
		info.Validated = false
	}
	return info
}
