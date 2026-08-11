package tlsdiag

import (
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

// benchResults builds n records each carrying full TLS diagnostics, so the
// benchmark renders every sentinel_tls_* series per target.
func benchResults(n int) fakeResults {
	recs := make([]store.Record, n)
	for i := range recs {
		info := fullInfo()
		// Vary the identity so the registry cannot collapse duplicate series and
		// the measurement reflects n distinct label sets.
		info.FingerprintSHA256 = fmt.Sprintf("%064x", i)
		info.Serial = fmt.Sprintf("%x", i)
		info.ExpiresAt = time.Unix(int64(2_000_000+i), 0)

		recs[i] = store.Record{
			Target: fmt.Sprintf("target-%d", i),
			Type:   "http",
			Labels: map[string]string{"environment": "prod", "service": "web"},
			Result: probe.Result{Success: true, Diagnostics: &tlsDiagnostics{info: info}},
		}
	}
	return fakeResults{recs: recs}
}

// BenchmarkCollectorGather measures the scrape cost of the TLS series at scale.
// It is the counterpart to BenchmarkHTTPCollectorGather: together they show how
// much of an HTTPS target's per-scrape render cost is certificate diagnostics.
func BenchmarkCollectorGather(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			reg := prometheus.NewRegistry()
			reg.MustRegister(NewCollector(benchResults(n)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := reg.Gather(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkInspect measures the per-probe inspection cost — the work added to
// every HTTPS handshake, as opposed to the per-scrape render cost above. Chain
// verification dominates it, so the OCSP variant isolates what the staple adds.
func BenchmarkInspect(b *testing.B) {
	c := newChain(b, refTime, chainOptions{})

	for _, tc := range []struct {
		name   string
		staple []byte
	}{
		{name: "no staple"},
		{name: "with staple", staple: stapleFor(b, c, ocsp.Good, refTime)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			state := stateFor(c.presented())
			state.OCSPResponse = tc.staple

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if info, _ := Inspect(state, testHost, refTime, c.roots, false); info == nil {
					b.Fatal("inspection returned no diagnostics")
				}
			}
		})
	}
}
