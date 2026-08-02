package http

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

// BenchmarkProbe measures the per-run overhead of the HTTP probe machinery
// (fresh connection, httptrace, validation) against a local server, isolating
// Sentinel's cost from any real network latency.
func BenchmarkProbe(b *testing.B) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	p, err := New(baseOpts(srv.URL))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := p.Probe(context.Background())
		if !res.Success {
			b.Fatalf("probe failed: %s", res.FailureReason)
		}
	}
}

// benchHTTPResults builds n HTTP records with full diagnostics for the collector.
func benchHTTPResults(n int) fakeResults {
	recs := make([]store.Record, n)
	for i := range recs {
		recs[i] = store.Record{
			Target: fmt.Sprintf("target-%d", i),
			Type:   ProbeType,
			Labels: map[string]string{"environment": "prod", "service": "web"},
			Result: probe.Result{
				Success: true,
				Timings: probe.Timings{DNS: time.Millisecond, Connect: 2 * time.Millisecond, TLS: 20 * time.Millisecond, TTFB: 30 * time.Millisecond, Download: time.Millisecond},
				Diagnostics: &Diagnostics{
					FinalURL:   "https://example/",
					StatusCode: 200,
					TLS:        &TLSInfo{ExpiresAt: time.Unix(int64(i), 0), RemainingDays: 42, HostnameValid: true, Valid: true},
				},
			},
		}
	}
	return fakeResults{recs: recs}
}

// BenchmarkHTTPCollectorGather measures the HTTP-specific scrape cost at scale.
func BenchmarkHTTPCollectorGather(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			reg := prometheus.NewRegistry()
			reg.MustRegister(NewCollector(benchHTTPResults(n)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := reg.Gather(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
