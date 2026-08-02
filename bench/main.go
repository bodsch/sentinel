// Command benchtool provides the moving parts for benchmarking Sentinel against
// the Prometheus blackbox_exporter: a local target server, a Sentinel config
// generator, a blackbox /probe latency sampler, a rate-limited load driver, a
// Sentinel /metrics scrape timer, and a per-phase timing comparison against real
// targets. Process lifecycle and RSS/CPU sampling live in the surrounding shell
// orchestrator.
package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
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
		fmt.Fprintln(os.Stderr, "usage: benchtool <target|genconfig|bb-probe|bb-load|scrape|compare> [flags]")
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
	case "compare":
		cmdCompare(os.Args[2:])
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
// compare: per-phase timing comparison against real targets. Probes each target
// through blackbox and reads Sentinel's own gauges for the same target, so the
// DNS/connect/TLS/TTFB/download/total bands can be compared side by side.
//
// Phase mapping (both are non-overlapping bands):
//
//	sentinel_http_dns_duration_seconds           <-> probe_http_duration_seconds{phase="resolve"}
//	sentinel_http_tcp_connect_duration_seconds   <-> probe_http_duration_seconds{phase="connect"}
//	sentinel_http_tls_handshake_duration_seconds <-> probe_http_duration_seconds{phase="tls"}
//	sentinel_http_ttfb_seconds                   <-> probe_http_duration_seconds{phase="processing"}
//	sentinel_http_download_duration_seconds      <-> probe_http_duration_seconds{phase="transfer"}
//	sentinel_probe_duration_seconds              <-> probe_duration_seconds
//
// sentinel_http_ttfb_seconds and sentinel_probe_duration_seconds are histograms
// (fed at probe time); their per-tick sample is the mean of the probes since the
// previous scrape, from the _sum/_count delta. The other phases are gauges.
//
// Caveat: Sentinel reports the final redirect hop; blackbox sums phases across
// all hops. For targets with redirects the per-phase values diverge (the total
// stays comparable), so redirect counts are printed alongside.
// ---------------------------------------------------------------------------

// phaseMap pairs a display label with the blackbox phase and Sentinel metric.
// hist marks Sentinel metrics that are histograms (fed at probe time) rather than
// last-value gauges: for those, the per-tick sample is the mean latency of the
// probes since the previous scrape, derived from the _sum/_count delta.
type phaseMap struct {
	label string
	bb    string // blackbox probe_http_duration_seconds phase label
	sent  string // sentinel metric name
	hist  bool   // sentinel metric is a histogram (read via _sum/_count delta)
}

var comparePhases = []phaseMap{
	{"dns", "resolve", "sentinel_http_dns_duration_seconds", false},
	{"connect", "connect", "sentinel_http_tcp_connect_duration_seconds", false},
	{"tls", "tls", "sentinel_http_tls_handshake_duration_seconds", false},
	{"ttfb", "processing", "sentinel_http_ttfb_seconds", true},
	{"download", "transfer", "sentinel_http_download_duration_seconds", false},
}

// compareTarget accumulates per-phase samples (in ms) for one target.
type compareTarget struct {
	name, url  string
	sent, bb   map[string][]float64 // phase label (+ "total") -> samples
	prevSum    map[string]float64   // last histogram _sum per phase key
	prevCount  map[string]float64   // last histogram _count per phase key
	sentRedir  float64
	bbRedir    float64
	sentStatus float64
	bbStatus   float64
}

func newCompareTarget(name, u string) *compareTarget {
	return &compareTarget{
		name: name, url: u,
		sent: map[string][]float64{}, bb: map[string][]float64{},
		prevSum: map[string]float64{}, prevCount: map[string]float64{},
	}
}

// observeHist reads a Sentinel histogram's _sum/_count for this target and, if new
// observations arrived since the last scrape, appends their mean latency (ms) as
// the sample for key. This mirrors the gauge path (one sample per scrape) while
// correctly reading the histogram form.
func (t *compareTarget) observeHist(snap, key, name string) {
	sum, count, ok := parseHistogramSumCount(snap, name, t.name)
	if !ok {
		return
	}
	dSum, dCount := sum-t.prevSum[key], count-t.prevCount[key]
	t.prevSum[key], t.prevCount[key] = sum, count
	if dCount > 0 {
		t.sent[key] = append(t.sent[key], dSum/dCount*1000)
	}
}

func cmdCompare(args []string) {
	f := flags(args)
	sentURL := f["sentinel"] // sentinel /metrics URL
	bbBase := f["bb"]        // e.g. http://127.0.0.1:9115/probe?module=http_2xx
	dur := atoi(f["dur"], 120)
	interval := atoi(f["interval"], 5)
	if sentURL == "" || bbBase == "" || f["targets"] == "" {
		fmt.Fprintln(os.Stderr, "compare needs -sentinel, -bb and -targets (name=url,name=url,...)")
		os.Exit(2)
	}

	var targets []*compareTarget
	for _, pair := range strings.Split(f["targets"], ",") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		targets = append(targets, newCompareTarget(kv[0], kv[1]))
	}

	client := &http.Client{Timeout: 15 * time.Second}
	ticks := dur / interval
	if ticks < 1 {
		ticks = 1
	}
	fmt.Printf("compare  targets=%d dur=%ds interval=%ds ticks=%d\n", len(targets), dur, interval, ticks)

	for tick := 0; tick < ticks; tick++ {
		// blackbox: one live probe per target.
		for _, t := range targets {
			body := httpGet(client, bbBase+"&target="+url.QueryEscape(t.url))
			for _, ph := range comparePhases {
				if v, ok := parseBBPhase(body, ph.bb); ok {
					t.bb[ph.label] = append(t.bb[ph.label], v*1000)
				}
			}
			if v, ok := parseBare(body, "probe_duration_seconds"); ok {
				t.bb["total"] = append(t.bb["total"], v*1000)
			}
			if v, ok := parseBare(body, "probe_http_redirects"); ok {
				t.bbRedir = v
			}
			if v, ok := parseBare(body, "probe_http_status_code"); ok {
				t.bbStatus = v
			}
		}

		// sentinel: a single scrape covers every target.
		snap := httpGet(client, sentURL)
		for _, t := range targets {
			for _, ph := range comparePhases {
				if ph.hist {
					t.observeHist(snap, ph.label, ph.sent)
				} else if v, ok := parseLabeled(snap, ph.sent, t.name); ok {
					t.sent[ph.label] = append(t.sent[ph.label], v*1000)
				}
			}
			// probe_duration_seconds is a histogram (total run duration).
			t.observeHist(snap, "total", "sentinel_probe_duration_seconds")
			if v, ok := parseLabeled(snap, "sentinel_http_redirects", t.name); ok {
				t.sentRedir = v
			}
			if v, ok := parseLabeled(snap, "sentinel_http_status_code", t.name); ok {
				t.sentStatus = v
			}
		}

		if tick < ticks-1 {
			time.Sleep(time.Duration(interval) * time.Second)
		}
	}

	// report
	for _, t := range targets {
		fmt.Printf("\n== %s (%s)\n", t.name, t.url)
		fmt.Printf("   status sent=%.0f bb=%.0f | redirects sent=%.0f bb=%.0f%s\n",
			t.sentStatus, t.bbStatus, t.sentRedir, t.bbRedir,
			redirNote(t.sentRedir, t.bbRedir))
		fmt.Printf("   %-9s %12s %12s %10s\n", "phase", "sentinel(ms)", "blackbox(ms)", "delta")
		for _, ph := range append([]phaseMap{}, comparePhases...) {
			printCompareRow(ph.label, t.sent[ph.label], t.bb[ph.label])
		}
		printCompareRow("total", t.sent["total"], t.bb["total"])
	}
}

func printCompareRow(label string, sent, bb []float64) {
	sm, sn := meanN(sent)
	bm, bn := meanN(bb)
	delta := ""
	if sn > 0 && bn > 0 {
		delta = fmt.Sprintf("%+.2f", sm-bm)
	}
	fmt.Printf("   %-9s %12s %12s %10s\n", label, meanCell(sm, sn), meanCell(bm, bn), delta)
}

func redirNote(a, b float64) string {
	if a > 0 || b > 0 {
		return "  (redirects: per-phase not directly comparable; compare total)"
	}
	return ""
}

func meanN(xs []float64) (float64, int) {
	if len(xs) == 0 {
		return 0, 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs)), len(xs)
}

func meanCell(m float64, n int) string {
	if n == 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f (n=%d)", m, n)
}

func httpGet(c *http.Client, u string) string {
	resp, err := c.Get(u)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// parseBare reads an unlabeled metric line: `<name> <value>`.
func parseBare(body, name string) (float64, bool) {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `\s+([0-9.eE+-]+)`)
	if m := re.FindStringSubmatch(body); m != nil {
		v, err := strconv.ParseFloat(m[1], 64)
		return v, err == nil
	}
	return 0, false
}

// parseBBPhase reads probe_http_duration_seconds{phase="<phase>"}.
func parseBBPhase(body, phase string) (float64, bool) {
	re := regexp.MustCompile(`(?m)^probe_http_duration_seconds\{phase="` + regexp.QuoteMeta(phase) + `"\}\s+([0-9.eE+-]+)`)
	if m := re.FindStringSubmatch(body); m != nil {
		v, err := strconv.ParseFloat(m[1], 64)
		return v, err == nil
	}
	return 0, false
}

// parseLabeled reads a metric line carrying a target="<name>" label.
func parseLabeled(body, name, target string) (float64, bool) {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `\{[^}]*\btarget="` + regexp.QuoteMeta(target) + `"[^}]*\}\s+([0-9.eE+-]+)`)
	if m := re.FindStringSubmatch(body); m != nil {
		v, err := strconv.ParseFloat(m[1], 64)
		return v, err == nil
	}
	return 0, false
}

// parseHistogramSumCount reads a Prometheus histogram's _sum and _count series for
// the given target. It returns ok=false unless both are present.
func parseHistogramSumCount(body, name, target string) (sum, count float64, ok bool) {
	s, okS := parseLabeled(body, name+"_sum", target)
	c, okC := parseLabeled(body, name+"_count", target)
	if !okS || !okC {
		return 0, 0, false
	}
	return s, c, true
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
