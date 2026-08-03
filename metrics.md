# Sentinel Metrics Specification

## Overview

Sentinel exposes monitoring data through a Prometheus-compatible metrics endpoint.

The metric design follows these principles:

- stable metric names
- predictable labels
- low cardinality
- detailed diagnostics outside of Prometheus labels
- support for alerting and dashboards

Endpoint:

```
GET /metrics
```

---

## Naming Convention

All metrics use the prefix:

```
sentinel_
```

The general structure:

```
sentinel_<component>_<measurement>
```

Examples:

```
sentinel_probe_success

sentinel_http_ttfb_seconds

sentinel_tls_certificate_expiry_timestamp_seconds
```

---

## Common Labels

Labels come from a **fixed, validated set** — this exact list. Arbitrary user tags are *not* turned
into labels: a `tags:` key outside this set is rejected at config validation time, which protects
against accidental cardinality explosions. Free-form tags-as-labels (with sanitizing and governance)
are a later feature.

| Label| Description |
| :--- | :---- |
| "target"| configured probe name         |
| "type"| probe type                      |
| "environment"| deployment environment   |
| "location"| probe location              |
| "service"| monitored service            |

Example:

```
sentinel_probe_success{
    target="homepage",
    type="http",
    environment="production"
}
```

---

## Build Info

```
sentinel_build_info
```

Type: `Gauge`, always `1`. Build metadata rides in the labels rather than the
value:

```
sentinel_build_info{version="0.2.0",commit="abc1234",go_version="go1.26"} 1
```

---

## Probe State Metrics

### Probe Success

Indicates whether the last probe execution succeeded.

```
sentinel_probe_success
```

Values:

```
1 = successful

0 = failed
```

Example:

```
sentinel_probe_success{
    target="homepage"
} 1
```

---

## Probe Duration

Distribution of total probe run duration, over all probe types.

```
sentinel_probe_duration_seconds
```

Type:

```
Histogram   (0.2 — was a Gauge in 0.1)
```

It is a **histogram fed at probe time** (see *Histograms* below), not a
scrape-time gauge: because Sentinel probes more often than Prometheus scrapes,
every probe is recorded, not just the last one visible at a scrape. Only
**successful** probes are observed, so timeouts and fast failures do not distort
the latency distribution (failure is carried by `sentinel_probe_success`).

Example (bucket / sum / count series):

```
sentinel_probe_duration_seconds_bucket{target="homepage",le="0.25"} 12
sentinel_probe_duration_seconds_sum{target="homepage"} 1.83
sentinel_probe_duration_seconds_count{target="homepage"} 12
```

Query the p95 with:

```
histogram_quantile(0.95, rate(sentinel_probe_duration_seconds_bucket[5m]))
```

---

## Last Successful Probe

Unix timestamp of the last successful execution.

```
sentinel_probe_last_success_timestamp_seconds
```

Useful for detecting stale probes.

---

## Skipped Probes

Counter of probe runs that were skipped because a previous run of the same target was still in
flight (overload protection, see the scheduler). A rising rate indicates the interval is too tight
for how long the target takes to probe.

```
sentinel_probe_skipped_total
```

Type:

```
Counter
```

---

## Error Classification

The primary alerting signal is always `sentinel_probe_success` (see above). The failure *reason*
is exposed separately as an **info metric**:

```
sentinel_probe_failure_info
```

Labels:

```
reason
```

Possible values (0.1 set):

```
dns_error

tcp_timeout

connection_refused

tls_error

certificate_expired

certificate_invalid

redirect_loop

redirect_limit_exceeded

downgrade

http_status_error

validation_failed

timeout

network_error
```

`network_error` is the catch-all for network-level failures that do not match a
more specific reason, so an unusual error is never silently misclassified.

Example:

```
sentinel_probe_failure_info{
    target="homepage",
    reason="redirect_loop"
} 1
```

**Vanishing semantics (important).** The reason is *not* modelled as a fixed metric whose label
value changes over time — that would leave orphaned time series (yesterday's `tls_error=1` lingering
next to today's `dns_error=1`). Instead the info series is emitted **only while the probe is
failing** and is **not emitted at all on success**. Because the state collector reads the result
store at scrape time, this is trivial: on success it simply skips the series. At any moment a
target has exactly one reason series, or none. Alert on `sentinel_probe_success == 0`; use the
info series to explain *why*.

---

## HTTP Metrics

### HTTP Status Code

```
sentinel_http_status_code
```

Example:

```
sentinel_http_status_code{
    target="homepage"
} 200
```

---

## HTTP Timing Breakdown

Sentinel separates HTTP phases.

### DNS Lookup

```
sentinel_http_dns_duration_seconds
```

---

### TCP Connection

```
sentinel_http_tcp_connect_duration_seconds
```

---

###TLS Handshake

```
sentinel_http_tls_handshake_duration_seconds
```

---

### Time To First Byte

Distribution of the time to the first response byte — one of the most important
application performance indicators.

```
sentinel_http_ttfb_seconds
```

Type:

```
Histogram   (0.2 — was a Gauge in 0.1)
```

Like `sentinel_probe_duration_seconds`, it is a **histogram fed at probe time**,
recording every successful HTTP probe (skipping non-HTTP records, failures, and
runs with no measured first byte). The other HTTP phase timings
(`http_dns_duration_seconds`, `http_tcp_connect_duration_seconds`,
`http_tls_handshake_duration_seconds`, `http_download_duration_seconds`) remain
last-value gauges.

Example:

```
sentinel_http_ttfb_seconds_bucket{target="api",le="0.1"} 40
sentinel_http_ttfb_seconds_sum{target="api"} 3.1
sentinel_http_ttfb_seconds_count{target="api"} 40
```

---

### Response Download

```
sentinel_http_download_duration_seconds
```

---

### Response Size / Transfer Rate (planned)

> Not emitted yet. `sentinel_http_response_size_bytes` and
> `sentinel_http_transfer_rate_bytes_per_second` are planned; today only the
> download *duration* (`sentinel_http_download_duration_seconds`) is exported.

---

## Redirect Metrics

### Redirect Count

```
sentinel_http_redirects
```

Type: `Gauge`. The number of redirects followed on the last probe.

---

### Redirect loop / limit (failure reasons, not metrics)

Redirect loops and exceeding the redirect limit are **not** separate metrics.
They surface as the `reason` label on `sentinel_probe_failure_info`
(`reason="redirect_loop"` / `reason="redirect_limit_exceeded"`), alongside the
other classified failure reasons.

---

### Final URL

Not exported as a normal label.

Reason:

URLs create unbounded cardinality.

Instead:

- available through Debug API
- available in structured logs

---

## TLS Metrics

### Certificate Expiration

Unix timestamp:

```
sentinel_tls_certificate_expiry_timestamp_seconds
```

---

### Certificate Remaining Days

Convenience metric:

```
sentinel_tls_certificate_remaining_days
```
Example:

```
sentinel_tls_certificate_remaining_days{
    target="homepage"
} 42
```

---

### Certificate Validation

```
sentinel_tls_certificate_valid
```

Values:

```
1 = valid (chain trusted, hostname matches, not expired)

0 = invalid
```

`1` requires the certificate chain to verify against the trusted roots (system
roots, or a target's `tls.ca_file`), the hostname to match, and the validity
window to be current. It stays honest even when a target sets
`tls.insecure_skip_verify` — an accepted-but-untrusted certificate reports `0`
here while the probe still succeeds, so you can alert on `== 0` regardless.

---

## DNS Metrics

### DNS Query Duration

```
sentinel_dns_query_duration_seconds
```

---

### DNS Response Code

```
sentinel_dns_response_code
```

Examples:

```
0  NOERROR

3  NXDOMAIN
```

---

### DNS Record Count

```
sentinel_dns_answer_count
```

---

## TCP Metrics

### TCP Connect Duration

```
sentinel_tcp_connect_duration_seconds
```

Type: `Gauge`. The connection-establishment time of the last probe, in seconds
(includes name resolution). Exposed for `tcp` targets.

Availability is not a separate metric: the generic `sentinel_probe_success`
already reports 1/0 for every target, TCP included, and the total time also
feeds the `sentinel_probe_duration_seconds` histogram.

---

## Runtime / Self-Observability Metrics

Sentinel exposes the standard Go runtime and process collectors so its own
health can be monitored alongside the probe results. They are registered in
production via `metrics.RegisterRuntimeCollectors` and are intentionally kept
off test/benchmark registries.

Go runtime (all platforms):

```
go_goroutines
go_threads
go_memstats_alloc_bytes
go_memstats_heap_inuse_bytes
go_gc_duration_seconds
```

Process (Linux exposes the full set; macOS reports a subset — see below):

```
process_cpu_seconds_total
process_open_fds
process_max_fds
process_start_time_seconds
process_resident_memory_bytes   # Linux only
process_virtual_memory_bytes    # Linux only
```

> **Platform note:** `process_resident_memory_bytes` and
> `process_virtual_memory_bytes` are reported on Linux (the primary deployment
> target). On macOS the process collector still exposes CPU, file-descriptor,
> and start-time series but omits the resident/virtual memory gauges.

Sentinel also exposes the cost of serving its own metrics endpoint:

```
sentinel_scrape_duration_seconds
```

The time to **gather** all series on the last scrape — the O(N) render cost of
building the metric families. It deliberately excludes the HTTP encoding and the
network write to the scraper, so a slow scraper does not inflate it (the full
round-trip is already Prometheus' own `scrape_duration_seconds`). It is set after
a gather completes, so the value reflects the previous scrape and appears one
scrape later; with overlapping scrapes it is the most recent scrape's value
(a plain gauge is last-writer-wins). Use it to size Prometheus' `scrape_timeout`
(see *Operating at scale* below).

Typical operational queries:

```
rate(process_cpu_seconds_total[5m])   # Sentinel's own CPU usage
go_goroutines                         # goroutine growth / leaks
process_resident_memory_bytes         # RSS trend as target count grows
max_over_time(sentinel_scrape_duration_seconds[1h])  # recent worst-case render time
```

---

## Operating at scale

Metrics are rendered live on every scrape: each collector walks the result store
and emits a fresh series per target. The cost is therefore **O(N)** in the number
of targets — an HTTP target emits ~10 scrape-time state series (success,
last-success, DNS/TCP/TLS/download timings, status, redirects, TLS diagnostics).
The latency histograms (`probe_duration`, `http_ttfb`) are separate: they are fed
at probe time and each expands to `buckets + 2` series.

Measured cost (18-core arm64; see `docs/benchmark-vs-blackbox.md`):

| Targets | Gather (render) — `sentinel_scrape_duration_seconds` | Full `/metrics` serve — Prometheus `scrape_duration_seconds` |
|---|---|---|
| 1 000  | ~9 ms   | ~20 ms  |
| 10 000 | ~120 ms | ~260 ms |

So the render itself is roughly **~12 µs per HTTP target**, and the full serve
(render + encode + network) about twice that. Most of the cost is the Prometheus
client library constructing and encoding the series (not Sentinel logic), so it
is inherent to producing N series rather than something a code change removes.

### Sizing `scrape_timeout`

- Watch `sentinel_scrape_duration_seconds` (the render cost) and set Prometheus'
  `scrape_timeout` comfortably above it — a factor of 2–3 leaves headroom for the
  encoding and network transfer the metric excludes, plus load spikes:

  ```yaml
  scrape_configs:
    - job_name: sentinel
      scrape_interval: 30s
      scrape_timeout: 10s      # must exceed sentinel_scrape_duration_seconds
      static_configs:
        - targets: ["sentinel:8080"]
  ```

- Keep `scrape_timeout` < `scrape_interval` (Prometheus requires this).
- Alert when the render cost approaches the timeout, e.g.
  `sentinel_scrape_duration_seconds > 0.5 * scrape_timeout`.

### Cheapest lever: scrape less often

Sentinel probes on its own tickers, **decoupled from the scrape** — so the scrape
frequency and the probe frequency are independent. The O(N) render cost is paid
once per *scrape*, not per probe, so simply **raising `scrape_interval`** (e.g.
30 s → 60 s) pays that cost less often *without* losing probe freshness: targets
still run at their configured `interval` (e.g. every 5 s), and the store always
holds their latest result.

This is a property the blackbox_exporter's pull model cannot offer — there a
longer scrape interval directly means less frequent probing. Reach for this
before adding instances: it is a one-line Prometheus change with no new moving
parts. The only trade-off is metric resolution in Prometheus (you sample the
current state less often), not probe coverage.

### When one instance is not enough

If probe CPU/RAM on a single machine — not the scrape cost — is the limit, or you
want fault isolation or multiple vantage points, **shard**: run several Sentinel
instances, each with a disjoint slice of the targets, and scrape each separately.
Every instance then probes and renders only its own share.

Sentinel deliberately keeps only current state, so sharding needs **no
coordination** (no leader election, no shared state) — Prometheus remains the
single source of truth. A stateless hash split (each instance keeps the targets
whose name hashes to its shard index) is planned; see `Roadmap.md`. Until then,
partition by hand with one config file per instance — but ensure the slices are
**disjoint and complete**: overlap double-probes a target (extra load, duplicate
series), a gap leaves it unmonitored.

---

## Histograms

**Implemented in 0.2.** Latency histograms accumulate *observations* and must be
fed at probe time via `.Observe()` — a different lifecycle from the scrape-time
state collectors. Sentinel feeds them through the scheduler's observer hook: as
each probe completes, its result is handed to observers that record into
persistent `HistogramVec`s. This is deliberately *not* the scrape-time model —
because Sentinel probes more often than Prometheus scrapes, a scrape-time gauge
would only ever expose the last probe, while the histogram captures every one.

Two latency metrics are histograms (they replaced the 0.1 gauges of the same
name — a breaking change for consumers that read them as gauges):

| Metric | Scope |
|---|---|
| `sentinel_probe_duration_seconds` | total run duration, all probe types |
| `sentinel_http_ttfb_seconds` | HTTP time-to-first-byte |

Only **successful** probes are observed, so timeouts and fast failures do not
distort the distributions. The remaining phase timings (DNS/TCP/TLS/download)
stay last-value gauges to bound cardinality — each histogram adds
`buckets + 2` series per target.

Shared buckets (seconds), spanning fast local responses to near-timeout runs:

```
0.005  0.01  0.025  0.05  0.1  0.25  0.5  1  2.5  5  10
```

This allows queries like:

```
histogram_quantile(0.95, rate(sentinel_http_ttfb_seconds_bucket[5m]))
```

> **Caveat:** histogram series are persistent, not read live from the store, so a
> removed target's series linger until the process restarts (unlike the state
> gauges, which vanish as soon as the target leaves the store).

---

## Baseline Metrics

Future feature.

Sentinel can calculate deviations against historical behavior.

Example:

```
sentinel_http_ttfb_baseline_seconds

sentinel_http_ttfb_deviation_ratio
```

Example:

```
Current:

300ms

Baseline:

50ms

Deviation:

6x
```

Possible alert:

```
sentinel_http_ttfb_deviation_ratio > 5
```

---

## Recommended Alerts

### Service unavailable

```
sentinel_probe_success == 0
```

---

### Redirect Loop

```
sentinel_probe_failure_info{reason="redirect_loop"} == 1
```

---

### Slow Response

```
histogram_quantile(
  0.95,
  rate(
    sentinel_http_ttfb_seconds_bucket[10m]
  )
) > 1
```

---

### Certificate Expiring

```
sentinel_tls_certificate_remaining_days < 14
```

---

## Metrics Design Rules

The following data must not become labels:

- complete URLs
- error messages
- redirect chains
- response bodies
- certificate subjects
- HTTP headers

These belong into:

- logs
- debug API
- traces
- external storage

---

## Summary

Sentinel metrics are designed to answer three questions:

1. Is the service available?
2. Is the service becoming slower?
3. What part of the request path causes the problem?

The metric model intentionally provides more diagnostic value than a simple success/failure exporter while remaining Prometheus-compatible.
