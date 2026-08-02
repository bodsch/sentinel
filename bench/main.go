// Command benchtool provides the moving parts for benchmarking Sentinel against
// the Prometheus blackbox_exporter: a local target server, a Sentinel config
// generator, a blackbox /probe latency sampler, a rate-limited load driver and
// a Sentinel /metrics scrape timer. Process lifecycle and RSS/CPU sampling live
// in the surrounding shell orchestrator.
package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: benchtool <target|genconfig|bb-probe|bb-load|scrape> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "target":
		cmdTarget(os.Args[2:])
	case "genconfig":
		cmdGenConfig(os.Args[2:])
	case "bb-probe":
		cmdBBProbe(os.Args[2:])
	case "bb-load":
		cmdBBLoad(os.Args[2:])
	case "scrape":
		cmdScrape(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// ---------------------------------------------------------------------------
// tiny flag parsing (stdlib flag would collide with our subcommand style)
// ---------------------------------------------------------------------------

func flags(args []string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(args); i++ {
		k := strings.TrimLeft(args[i], "-")
		if i+1 < len(args) {
			m[k] = args[i+1]
			i++
		} else {
			m[k] = "true"
		}
	}
	return m
}

func atoi(s string, def int) int {
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

// ---------------------------------------------------------------------------
// target: a minimal, low-overhead HTTP server both probers hit.
// ---------------------------------------------------------------------------

func cmdTarget(args []string) {
	f := flags(args)
	addr := f["addr"]
	if addr == "" {
		addr = ":9099"
	}
	var hits int64
	body := []byte("ok")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/hits", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%d\n", atomic.LoadInt64(&hits))
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	fmt.Fprintf(os.Stderr, "target listening on %s\n", addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// genconfig: emit a Sentinel YAML config with N identical HTTP targets.
// ---------------------------------------------------------------------------

func cmdGenConfig(args []string) {
	f := flags(args)
	n := atoi(f["n"], 100)
	url := f["url"]
	interval := f["interval"]
	if interval == "" {
		interval = "10s"
	}
	timeout := f["timeout"]
	if timeout == "" {
		timeout = "3s"
	}
	out := f["out"]

	var b strings.Builder
	fmt.Fprintf(&b, "defaults:\n  interval: %s\n  timeout: %s\n  http:\n    method: GET\n    follow_redirects: true\n    max_redirects: 10\n    max_body_bytes: 1048576\n\ntargets:\n", interval, timeout)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "  - name: t-%d\n    tags:\n      service: bench\n      environment: bench\n    http:\n      url: %s\n      expect:\n        status: 200\n", i, url)
	}
	if out == "" {
		fmt.Print(b.String())
		return
	}
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d targets)\n", out, n)
}

// ---------------------------------------------------------------------------
// bb-probe: dimension A. Hit blackbox /probe N times and report both the
// end-to-end HTTP latency and blackbox's self-reported probe_duration_seconds.
// ---------------------------------------------------------------------------

var reProbeDuration = regexp.MustCompile(`(?m)^probe_duration_seconds\s+([0-9.eE+-]+)`)

func cmdBBProbe(args []string) {
	f := flags(args)
	url := f["url"] // full /probe?...&module=...&target=...
	n := atoi(f["n"], 2000)
	conc := atoi(f["c"], 1)

	client := &http.Client{Timeout: 10 * time.Second}
	var (
		mu       sync.Mutex
		e2e      []float64
		internal []float64
		fails    int64
	)
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			resp, err := client.Get(url)
			if err != nil {
				atomic.AddInt64(&fails, 1)
				return
			}
			bdy, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			d := time.Since(start).Seconds() * 1000
			var pd float64 = -1
			if m := reProbeDuration.FindSubmatch(bdy); m != nil {
				pd, _ = strconv.ParseFloat(string(m[1]), 64)
				pd *= 1000
			}
			ok := strings.Contains(string(bdy), "probe_success 1")
			mu.Lock()
			if ok {
				e2e = append(e2e, d)
				if pd >= 0 {
					internal = append(internal, pd)
				}
			} else {
				fails++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	fmt.Printf("bb-probe  n=%d conc=%d fails=%d\n", n, conc, fails)
	printDist("  end-to-end /probe (ms)", e2e)
	printDist("  probe_duration (ms)   ", internal)
}

// ---------------------------------------------------------------------------
// bb-load: dimension B driver. Sustain `rate` probe requests/sec against
// blackbox for `dur`, emulating Prometheus scraping N targets every interval.
// ---------------------------------------------------------------------------

func cmdBBLoad(args []string) {
	f := flags(args)
	url := f["url"]
	rate := atoi(f["rate"], 100)
	durSec := atoi(f["dur"], 30)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        rate * 2,
			MaxIdleConnsPerHost: rate * 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	var (
		mu    sync.Mutex
		lat   []float64
		fails int64
		sent  int64
	)
	sem := make(chan struct{}, rate*4+16) // bound in-flight

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durSec)*time.Second)
	defer cancel()

	interval := time.Second / time.Duration(rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var wg sync.WaitGroup
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-ticker.C:
			select {
			case sem <- struct{}{}:
			default:
				atomic.AddInt64(&fails, 1) // driver saturated: count as a miss
				continue
			}
			wg.Add(1)
			atomic.AddInt64(&sent, 1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				start := time.Now()
				resp, err := client.Get(url)
				if err != nil {
					atomic.AddInt64(&fails, 1)
					return
				}
				bdy, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				d := time.Since(start).Seconds() * 1000
				ok := strings.Contains(string(bdy), "probe_success 1")
				mu.Lock()
				if ok {
					lat = append(lat, d)
				} else {
					fails++
				}
				mu.Unlock()
			}()
		}
	}
	wg.Wait()

	fmt.Printf("bb-load   rate=%d/s dur=%ds sent=%d ok=%d fails=%d\n", rate, durSec, sent, len(lat), fails)
	printDist("  /probe latency (ms)", lat)
}

// ---------------------------------------------------------------------------
// scrape: measure Sentinel /metrics scrape latency and pull one gauge value.
// ---------------------------------------------------------------------------

func cmdScrape(args []string) {
	f := flags(args)
	url := f["url"]
	n := atoi(f["n"], 50)
	metric := f["metric"] // optional gauge name to extract

	client := &http.Client{Timeout: 10 * time.Second}
	var lat []float64
	var lastVal string
	var lastSize int
	for i := 0; i < n; i++ {
		start := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		bdy, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lat = append(lat, time.Since(start).Seconds()*1000)
		lastSize = len(bdy)
		if metric != "" {
			re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(metric) + `\s+([0-9.eE+-]+)`)
			if m := re.FindSubmatch(bdy); m != nil {
				lastVal = string(m[1])
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Printf("scrape    n=%d body=%dB", n, lastSize)
	if metric != "" {
		fmt.Printf(" %s=%s", metric, lastVal)
	}
	fmt.Println()
	printDist("  /metrics latency (ms)", lat)
}

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------

func printDist(label string, xs []float64) {
	if len(xs) == 0 {
		fmt.Printf("%s: no samples\n", label)
		return
	}
	sort.Float64s(xs)
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	fmt.Printf("%s: n=%d mean=%.3f p50=%.3f p90=%.3f p99=%.3f max=%.3f\n",
		label, len(xs), mean, pct(xs, 50), pct(xs, 90), pct(xs, 99), xs[len(xs)-1])
}

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
