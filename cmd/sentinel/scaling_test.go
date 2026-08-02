package main

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/clock"
	"bodsch.me/sentinel/internal/metrics"
	httpprobe "bodsch.me/sentinel/internal/probe/http"
	"bodsch.me/sentinel/internal/scheduler"
	"bodsch.me/sentinel/internal/store"
)

// TestScalingProfile runs the full runtime against a local server at several
// target counts and reports the resource profile (goroutines, heap, scrape
// latency). It is a measurement, not an assertion, so it is gated behind an
// environment variable and skipped in normal test runs:
//
//	SENTINEL_SCALING=1 go test -run TestScalingProfile -v ./cmd/sentinel/
func TestScalingProfile(t *testing.T) {
	if os.Getenv("SENTINEL_SCALING") == "" {
		t.Skip("set SENTINEL_SCALING=1 to run the scaling profile")
	}

	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	t.Logf("%-6s %-8s %-11s %-13s %-10s", "N", "stored", "goroutines", "heapAlloc", "scrape")
	for _, n := range []int{100, 500, 1000} {
		st := store.New()
		sched := scheduler.New(scheduler.Options{Clock: clock.Real{}, Store: st})

		for i := 0; i < n; i++ {
			name := fmt.Sprintf("target-%d", i)
			p, err := httpprobe.New(httpprobe.Options{
				Name: name, Method: "GET", URL: srv.URL,
				Timeout: 3 * time.Second, FollowRedirects: true,
				MaxRedirects: 10, MaxBodyBytes: 1 << 20, ExpectStatus: 200,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := sched.Add(scheduler.JobSpec{
				Name: name, Type: httpprobe.ProbeType, Interval: time.Second, Prober: p,
			}); err != nil {
				t.Fatal(err)
			}
		}

		reg := metrics.NewRegistry()
		reg.MustRegister(metrics.NewProbeCollector(st, sched))
		reg.MustRegister(httpprobe.NewCollector(st))

		ctx, cancel := context.WithCancel(context.Background())
		go sched.Run(ctx)

		// Let every target probe at least twice.
		time.Sleep(3 * time.Second)

		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		goroutines := runtime.NumGoroutine()

		start := time.Now()
		if _, err := reg.Gather(); err != nil {
			t.Fatal(err)
		}
		scrape := time.Since(start)

		t.Logf("%-6d %-8d %-11d %-10dKiB %-10v", n, st.Len(), goroutines, m.HeapAlloc/1024, scrape)

		cancel()
		time.Sleep(300 * time.Millisecond) // allow the drain before the next round
	}
}
