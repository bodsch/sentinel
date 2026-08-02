package metrics

import (
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/scheduler"
	"bodsch.me/sentinel/internal/store"
)

func benchResults(n int) fakeResults {
	recs := make([]store.Record, n)
	for i := range recs {
		success := i%10 != 0 // ~10% failing, exercising the failure_info path
		reason := probe.ReasonNone
		if !success {
			reason = probe.ReasonTimeout
		}
		recs[i] = store.Record{
			Target: fmt.Sprintf("target-%d", i),
			Type:   "http",
			Labels: map[string]string{"environment": "prod", "service": "web"},
			Result: probe.Result{
				Success:       success,
				FailureReason: reason,
				Duration:      time.Duration(i) * time.Millisecond,
				Timestamp:     time.Unix(int64(i), 0),
			},
			LastSuccess: time.Unix(int64(i), 0),
		}
	}
	return fakeResults{recs: recs}
}

func benchSkips(n int) fakeSkips {
	stats := make([]scheduler.JobStat, n)
	for i := range stats {
		stats[i] = scheduler.JobStat{
			Name:    fmt.Sprintf("target-%d", i),
			Type:    "http",
			Labels:  map[string]string{"environment": "prod", "service": "web"},
			Skipped: int64(i % 3),
		}
	}
	return fakeSkips{stats: stats}
}

// BenchmarkProbeCollectorGather measures the cost of a full /metrics scrape of
// the generic probe collector at several target counts.
func BenchmarkProbeCollectorGather(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			reg := prometheus.NewRegistry()
			reg.MustRegister(NewProbeCollector(benchResults(n), benchSkips(n)))
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
