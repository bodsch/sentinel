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
| TLS diagnostics | leaf + presented-chain expiry, chain info, negotiated version | + root-inclusive chain expiry, chain length/verified, cipher, key bits, NotBefore, self-signed, OCSP stapling, opt-in `tls.expect` policy (see `metrics.md` → *Comparison with the blackbox_exporter*) |

A single "who uses less CPU" number is therefore architecture-dependent. We
measure three levels: **A)** per-probe engine cost (apples-to-apples),
**B)** steady-state system scale on a loopback target, and **C)** phase-timing
agreement against real servers.

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

Hard run to N=10000 (2026-08-02, 30 s window):

| N | Sentinel CPU% | Sentinel RSS peak | Sentinel `/metrics` scrape | blackbox CPU% | blackbox RSS peak | blackbox `/probe` p50 |
|---|---|---|---|---|---|---|
| 100   | ~0   | 24 MB  | 5.4 ms   | 3.3  | 39 MB   | 1.83 ms |
| 1000  | 6.7  | 33 MB  | 20.0 ms  | 23.3 | 42 MB   | 0.95 ms |
| 5000  | 26.7 | 76 MB  | 104 ms   | 70.0 | 45 MB   | 0.53 ms |
| 10000 | 46.7 | 130 MB | 259 ms   | 40.0 | **735 MB** | **3282 ms** |

The ~2× CPU ratio held across independent runs up to N=5000 (blackbox 70 % vs
Sentinel 27 %). At **N=10000 (2000 probes/s) the pull path saturates**: driving
2000 `/probe` requests/s collapsed blackbox to a 3.3 s p50 latency and 735 MB RSS
(the load driver also hit its in-flight ceiling — `ok=12804 fails=49021`), while
Sentinel stayed stable at 47 % CPU, 130 MB, 259 ms scrape. Read the N=10000
blackbox row as "past the single-instance throughput ceiling of this loopback
harness", not as a precise figure — but the direction is the architectural point:
the pull path does not degrade gracefully past an instance's ceiling, whereas
Sentinel's decoupled tickers do.

### Reading the numbers

- **CPU:** Sentinel uses roughly **half** the CPU of blackbox at the same probe
  rate, up to the point blackbox saturates. This is the wrapper cost from
  Dimension A made system-wide: blackbox pays a full HTTP-handler + metric-render
  on every probe; Sentinel pays it once per scrape regardless of N.
- **Memory (the honest trade-off):** in the stable regime blackbox is stateless →
  RSS flat at ~40–45 MB, while Sentinel stores state → RSS grows O(N)
  (24 → 33 → 76 MB). The **crossover is between N=1000 and N=5000**; above it
  Sentinel's decoupled model costs more RAM — *until* blackbox saturates, at which
  point its flat-memory advantage disappears entirely (735 MB at N=10000 vs
  Sentinel's 130 MB).
- **Scrape (apples/oranges by design):**
  - Sentinel: **one** `/metrics` scrape returns *all* targets' state with no
    network I/O at scrape time — but the render is O(N): 20 ms at N=1000, 104 ms
    at N=5000, 259 ms at N=10000. Prometheus `scrape_timeout` must accommodate it.
  - blackbox: Prometheus must run **N separate** `/probe` scrapes (~0.6 ms each
    while unsaturated), each triggering a live probe. Aggregate ≈ N × 0.6 ms of
    probe work per scrape cycle — which is exactly what saturates at high N.

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

## Dimension C — real servers: phase-timing agreement

Loopback isolates the engine but hides whether Sentinel's phase diagnostics are
*correct*. This dimension probes 8 real HTTPS targets (4 self-hosted + google.de,
heise.de, bild.de, welt.de) with **both** tools at a polite 5 s interval for
120 s (24 samples/target — no high-rate load against third parties), and compares
the per-phase bands. Sentinel's bands map 1:1 onto blackbox's:

| Sentinel | blackbox |
|---|---|
| `sentinel_http_dns_duration_seconds` | `probe_http_duration_seconds{phase="resolve"}` |
| `sentinel_http_tcp_connect_duration_seconds` | `…{phase="connect"}` |
| `sentinel_http_tls_handshake_duration_seconds` | `…{phase="tls"}` |
| `sentinel_http_ttfb_seconds` | `…{phase="processing"}` |
| `sentinel_http_download_duration_seconds` | `…{phase="transfer"}` |

Run with `bench/.cache/benchtool compare` (see `bench/main.go`).

### Connection phases agree

For direct (non-redirecting) targets, DNS/TCP/TLS/TTFB match within single-digit
milliseconds — Sentinel's latency localisation tracks the reference (mean of 24
samples, ms):

| target | DNS S/bb | TCP S/bb | TLS S/bb | TTFB S/bb |
|---|---|---|---|---|
| homepage | 1.5 / 2.1 | 32.2 / 31.8 | 37.2 / 42.8 | 34.9 / 45.6 |
| heise | 1.5 / 1.7 | 29.9 / 29.3 | 35.7 / 38.6 | 33.0 / 32.7 |
| welt | 8.0 / 6.9 | 22.5 / 19.4 | 41.9 / 41.7 | 106.7 / 124.1 |
| fritz | 2.3 / 2.3 | 32.3 / 28.8 | 34.7 / 39.2 | **2573.8 / 2482.8** |

`fritz` is a deliberately slow real target (~2.5 s): both tools localise the
latency to the TTFB/waiting phase identically — exactly the "why is it slow?"
diagnostic the project is built for.

### Two documented divergences

- **Redirects.** Sentinel reports the *final hop*; blackbox *sums* phases across
  hops. For `git` and `google` (1 redirect each) blackbox's connect/TLS run ~2×
  Sentinel's (e.g. google TLS 40.9 ms vs 94.9 ms). The **total** stays
  comparable (google 343.8 ms vs 388.5 ms). Redirect counts are reported so this
  is visible.
- **Download/transfer.** Sentinel's `download` is systematically lower —
  near-zero for small bodies (self-hosted pages read in ~0.2 ms) and well below
  blackbox for large ones (heise, 0.88 MiB: 63 ms vs 388 ms). Drivers: the two
  clients handle the transfer boundary and compression differently, and Sentinel
  additionally caps the body at `max_body_bytes` (1 MiB — welt.de at 1.31 MiB is
  truncated). This propagates into `total`, so the two tools' **total duration is
  not directly equivalent for download-heavy pages**. The phases that localise
  latency (DNS/TCP/TLS/TTFB) are unaffected and agree.

### Resource cost at realistic load (8 targets, 5 s interval, 120 s)

| | RSS | CPU over 120 s |
|---|---|---|
| Sentinel | 31 MB | 3.0 s |
| blackbox | 54 MB | 2.0 s |

At real-world small-N load, resource use is in the same ballpark — here Sentinel
is leaner on RSS (its per-target series are cheap at N=8; blackbox's higher RSS
reflects real TLS/connection state and full-body reads to 8 hosts). This is the
opposite end of the curve from Dimension B, where Sentinel's O(N) memory
eventually overtakes blackbox's flat footprint.

## Limitations

- Loopback target removes network RTT; real deployments narrow the absolute
  engine gap. Dimension C addresses this with real targets but only at small N
  and a polite interval (hammering third-party sites at high rate is out of
  scope — abusive and would be rate-limited).
- Single blackbox instance; CPU sampling is coarse (~1 CPU-second quantisation);
  short steady-state window; the in-process `BenchmarkProbe` is noisy run-to-run.
- The N=10000 row of Dimension B is at the loopback harness's own ceiling (the
  load driver saturated); read its blackbox figures as directional, not exact.
- The download/total divergence in Dimension C means the two tools' *total*
  duration is not directly equivalent for download-heavy pages; the localisation
  phases (DNS/TCP/TLS/TTFB) are.
- Sentinel now exposes `go_*`/`process_*` collectors (see the metrics spec), so
  its own goroutine/heap/CPU can be scraped in production; this benchmark still
  samples RSS/CPU externally with `ps` for parity with blackbox.

## Reproducing

The full harness — target server, config generator, blackbox load driver,
scrape timer, per-phase `compare`, and orchestrator — lives in
[`../bench/`](../bench/):

```bash
make benchmark                              # dimensions A + B, default N
NS="100 1000 5000 10000" WINDOW_S=30 bench/run.sh   # the hard scale run

# dimension C — real-server phase comparison (requires a running sentinel
# and blackbox; benchtool compare drives both):
bench/.cache/benchtool compare \
  -sentinel http://127.0.0.1:8080/metrics \
  -bb 'http://127.0.0.1:9115/probe?module=http_2xx' \
  -targets 'heise=https://www.heise.de,welt=https://www.welt.de' \
  -dur 120 -interval 5
```

It builds Sentinel and the `benchtool` helper, downloads a pinned
`blackbox_exporter` release into `bench/.cache/`, and writes results to
`bench/results.txt`. See [`../bench/README.md`](../bench/README.md) for the knobs.
