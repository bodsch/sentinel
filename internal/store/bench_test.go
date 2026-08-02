package store

import (
	"fmt"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// benchSizes are the target counts exercised by the store benchmarks.
var benchSizes = []int{100, 1000, 10000}

func fillStore(n int) *Store {
	s := New()
	for i := 0; i < n; i++ {
		s.Set(Record{
			Target: fmt.Sprintf("target-%d", i),
			Type:   "http",
			Labels: map[string]string{"environment": "prod", "service": "web"},
			Result: probe.Result{Success: true, Timestamp: time.Unix(int64(i), 0)},
		})
	}
	return s
}

// BenchmarkSnapshot measures the per-scrape cost of copying the whole store,
// which the metrics collector does on every /metrics request.
func BenchmarkSnapshot(b *testing.B) {
	for _, n := range benchSizes {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			s := fillStore(n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.Snapshot()
			}
		})
	}
}

// BenchmarkSet measures the write path (one probe result stored).
func BenchmarkSet(b *testing.B) {
	s := fillStore(1000)
	rec := Record{Target: "target-0", Type: "http", Result: probe.Result{Success: true, Timestamp: time.Unix(1, 0)}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Set(rec)
	}
}

// BenchmarkGet measures the point-read path.
func BenchmarkGet(b *testing.B) {
	s := fillStore(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = s.Get("target-500")
	}
}
