# Benchmark: Sentinel vs. Prometheus blackbox_exporter

Comparison of Sentinel against `blackbox_exporter 0.28.0` for HTTP probing. Both
run as **native binaries**; RSS/CPU are sampled uniformly with `ps` so the
numbers are comparable. The harness that produces these numbers lives in
[`../bench/`](../bench/) — run it with `make benchmark`.

## Why this is not a naive comparison

The two tools use fundamentally different probe models:

| | blackbox_exporter | Sentinel |
|---|---|---|
| Probe model | **Pull**: every `/probe` scrape triggers one *synchronous* probe | **Active/decoupled**: background tickers probe continuously; `/metrics` reads a snapshot |
| Work happens | at scrape time | on internal tickers |
| Scrape cost | = one full probe (network I/O) | ~O(N) memory read, no I/O |
| State kept | none between scrapes | per-target record + metric series |
| Timing method | `httptrace` (DNS/TCP/TLS/TTFB) | `httptrace` (same phases) |

A single "who uses less CPU" number is therefore architecture-dependent. We
measure two levels: **A)** per-probe engine cost (apples-to-apples) and
**B)** steady-state system scale.

## Method

- Host: 18-core arm64 (Darwin), Go 1.26.5.
- Target: a local loopback HTTP server returning `200 ok` — isolates the probe
  engine from network variance. In production the network RTT dominates both
  tools, so the *absolute* engine gap shrinks; this setup exposes the engine
  itself.
- Identical probe semantics: `GET`, expect status `200`, follow redirects,
  IPv4, 3 s timeout.
- Fair load model: at N targets and a 5 s interval, **both** systems perform
  `N/5` probes per second in aggregate. Sentinel probes N targets on tickers;
  a driver issues `N/5` `/probe` requests/s to blackbox, emulating Prometheus
  scraping N targets every 5 s.
- CPU% is derived from cumulative `ps` CPU time over a 15 s window; it is
  quantised (~1 CPU-second granularity) and directional, not exact to 0.1 %.
- Sentinel's in-process `BenchmarkProbe` uses fixed iterations (`-benchtime
  3000x`) and is noisy run-to-run (observed 0.16–0.29 ms/op across runs);
  treat its absolute value as a ballpark, not a precise figure.

## Dimension A — per-probe engine cost

Representative run (2026-08-02):

| Metric | Sentinel | blackbox |
|---|---|---|
| Probe engine proper | ~0.16–0.29 ms/op (159 allocs, 20.5 KB/op) | 0.257 ms (`probe_duration_seconds`, mean) |
| Full per-scrape cost | — | 0.464 ms end-to-end `/probe` (mean) |

**Reading it honestly:** the *probe itself* costs about the same in both tools —
roughly a quarter of a millisecond against a local target, and Sentinel's
in-process figure swings across that range between runs. There is **no reliable
engine-level advantage** for either side here.

The durable difference is the **wrapper**: blackbox renders a full Prometheus
text response on every `/probe` (handler + metric encoding), so each probe
Prometheus triggers costs ~0.46 ms end-to-end, not ~0.26 ms. Sentinel amortises
that — a probe writes to the store, and a single scrape reads *all* targets.
This wrapper cost, paid once per probe, is what shows up as the ~2× CPU gap in
Dimension B below.

## Dimension B — steady-state scale (aggregate probe rate = N/5 s)

Representative run (2026-08-02):

| N | Sentinel CPU% | Sentinel RSS peak | Sentinel `/metrics` scrape | blackbox CPU% | blackbox RSS peak | blackbox `/probe` |
|---|---|---|---|---|---|---|
| 100  | ~0  | 23 MB | 5.1 ms  | ~0   | 36 MB | 1.66 ms |
| 500  | 6.7 | 27 MB | 14.3 ms | 13.3 | 40 MB | 1.06 ms |
| 1000 | 6.7 | 33 MB | 19.0 ms | 20.0 | 40 MB | 0.87 ms |
| 2000 | 13.3| 44 MB | 36.0 ms | 33.3 | 41 MB | 0.63 ms |

The CPU column reproduced identically across two independent runs (a consequence
of the `ps` quantisation), so the ~2× ratio is robust despite the coarse units.

### Reading the numbers

- **CPU:** Sentinel uses roughly **half** the CPU of blackbox at the same probe
  rate. This is the wrapper cost from Dimension A made system-wide: blackbox
  pays a full HTTP-handler + metric-render on every probe; Sentinel pays it once
  per scrape regardless of N.
- **Memory (the honest trade-off):** blackbox is stateless → RSS flat at ~40 MB
  regardless of N. Sentinel stores state → RSS grows O(N), 23 → 44 MB. The
  **crossover is between N=1000 and N=2000**; above that, Sentinel's decoupled
  model costs more RAM.
- **Scrape (apples/oranges by design):**
  - Sentinel: **one** `/metrics` scrape (36 ms at N=2000, O(N) rendering)
    returns *all* targets' state with no network I/O at scrape time.
  - blackbox: Prometheus must run **N separate** `/probe` scrapes (~0.6 ms each,
    flat in N), but each one triggers a live probe. Aggregate ≈ N × 0.6 ms of
    probe work per scrape cycle.

### Bottom line

- The **probe engines are comparable** — neither has a reliable per-probe speed
  edge against a local target.
- blackbox: probe freshness **equals** the scrape interval, and probe load is
  **coupled** to Prometheus. Stateless, flat memory, but ~2× the CPU because
  every probe carries a full `/probe` HTTP response.
- Sentinel: probe cadence is **independent** of scrape; the scrape is a cheap
  read. About half the CPU, but memory grows with the number of targets.

Sentinel wins on CPU and on decoupling probe cadence from scrape load; blackbox
wins on flat memory at very high target counts and on operational simplicity
(stateless). The right choice depends on whether you value probe/scrape
decoupling and CPU efficiency (Sentinel) or a stateless, memory-flat sidecar
(blackbox).

## Limitations

- Loopback target removes network RTT; real deployments narrow the absolute
  engine gap.
- Single blackbox instance; CPU sampling is coarse (~1 CPU-second quantisation);
  short steady-state window; the in-process `BenchmarkProbe` is noisy run-to-run.
- Sentinel now exposes `go_*`/`process_*` collectors (see the metrics spec), so
  its own goroutine/heap/CPU can be scraped in production; this benchmark still
  samples RSS/CPU externally with `ps` for parity with blackbox.

## Reproducing

The full harness — target server, config generator, blackbox load driver,
scrape timer, and orchestrator — lives in [`../bench/`](../bench/):

```bash
make benchmark                        # default: N = 100 500 1000 2000
NS="100 1000 5000" bench/run.sh       # custom target counts
```

It builds Sentinel and the `benchtool` helper, downloads a pinned
`blackbox_exporter` release into `bench/.cache/`, and writes results to
`bench/results.txt`. See [`../bench/README.md`](../bench/README.md) for the knobs.
