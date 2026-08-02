# Sentinel Roadmap

## Project Status

Sentinel is currently in the design phase.

The roadmap focuses on building a stable monitoring foundation before adding advanced functionality.

The primary goal is a reliable synthetic monitoring engine with excellent Prometheus integration.

---

## Version 0.1 - Core Monitoring Engine (HTTP slice)

### Goal

Create a production-ready monitoring daemon for the **HTTP/HTTPS** use case, with the complete
runtime skeleton in place so further protocols slot in without reworking the core. Version 0.1 is a
deliberately narrow vertical slice — one protocol done end-to-end, not several done partially.

> Status: design decided, implementation pending. The list below is the **planned 0.1 scope**, not
> yet-shipped functionality.

---

### Core Runtime (scope)

- Go application structure (`cmd/sentinel` + `internal/*` + `pkg/version`)
- configuration loading (`defaults` + `targets`, no templates) and validation
- `--validate` dry-run and fail-fast startup
- scheduler: ticker-per-target + semaphore-bounded execution, skip-if-running
- probe lifecycle management with a typed `Result` and `FailureReason` enum
- single total timeout per target, full context cancellation
- graceful shutdown (drain, default 10s; in-flight probes discarded)
- structured logging (`log/slog`, JSON, fixed field schema)
- `Clock` interface for deterministic scheduler tests

---

### HTTP Monitoring (scope)

- HTTP/HTTPS checks, `GET` and `HEAD`
- fresh connection per run (full, comparable phase timings; no connection reuse)
- status code / body regex / header validators (via a `Validator` interface)
- `max_body_bytes` cap (default 1 MB)
- redirect handling: follow up to `max_redirects`, loop detection, HTTPS→HTTP downgrade detection
- TLS diagnostics: expiry, hostname match, remaining days (manual certificate inspection)
- HTTP timing instrumentation via `net/http/httptrace`

Metrics:

- total duration (across all redirect hops)
- DNS / TCP / TLS / TTFB / download duration (final hop)

---

### Prometheus Integration (scope)

- `/metrics` via a dedicated registry, plus `/healthz` and `/readyz` on `:8080`
- self-registering collectors; state read live at scrape time
- stable metric naming, fixed label set, error classification (`probe_failure_info`)
- `sentinel_build_info`
- **state gauges only** (histograms are 0.2)

---

## Version 0.2 - Advanced Diagnostics & More Protocols

### Goal

Increase diagnostic capabilities and expand beyond HTTP.

---

### DNS Monitoring

Implemented:

- A / AAAA / MX / TXT records against a configurable resolver
- RCODE, answer-count and query-timing metrics
- optional expected-answer validation (type-aware matching)
- EDNS0 + automatic TCP fallback on truncation

Planned:

- CNAME / SRV records
- DNSSEC validation

---

### TCP Monitoring

Planned:

- TCP connection checks
- timeout handling
- banner validation

---

### ICMP Monitoring

Planned:

- reachability checks
- latency measurement
- packet loss measurement
- (note: raw sockets require elevated privileges / `CAP_NET_RAW`; platform-specific handling)

---

### Metrics & Runtime

Planned:

- ~~histogram support (latency distributions, fed at probe time)~~
  **(implemented)**. `sentinel_probe_duration_seconds` (all types) and
  `sentinel_http_ttfb_seconds` are now histograms fed at probe time via the
  scheduler's observer hook, capturing every probe (not just the last one seen
  at scrape). They replaced the 0.1 gauges of the same name. See `metrics.md` →
  *Histograms*.
- in-probe retry with retry metrics
- ~~scrape performance at high target counts~~ **(addressed)**. `/metrics`
  rendering is O(N) (~259 ms at N=10000 — see `docs/benchmark-vs-blackbox.md`,
  Dimension B). Investigation showed the cost is ~95 % Prometheus client-library
  series construction/encoding (not Sentinel logic), so there is no large
  in-code render win — the scaling lever is operational. Delivered:
  the `sentinel_scrape_duration_seconds` self-metric (observe the per-scrape
  render cost) and a `metrics.md` → *Operating at scale* section with
  `scrape_timeout` sizing guidance and sharding advice. Cached-snapshot rendering
  is intentionally not pursued (it would break the live-at-scrape-time model);
  sharding remains the path past a few thousand targets per instance.

---

### HTTP Improvements

Planned:

- HTTP/2 optimization
- ~~custom request headers~~ **(implemented)**: `http.headers` sets request
  headers (a `Host` key maps to the request host); sent only to the target's own
  host, never carried across a redirect to a different host. See
  `configuration.md`.
- request body support
- ~~authentication~~ **(implemented)**: `http.basic_auth` and `http.bearer_token`
  (mutually exclusive with each other and an explicit Authorization header),
  applied same-host-only for leak safety. Secrets are inline; **planned
  follow-up**: `password_file` / `bearer_token_file` (and/or env references) so
  credentials need not live in the config and `--validate` can run without them.
- JSONPath validation
- XPath validation
- body size validation
- compression analysis
- ~~configurable `max_body_bytes` cap~~ **(implemented)**. Per-target override
  already worked via the normal `defaults` + target merge; added an explicit
  per-target opt-out (`max_body_bytes: 0` = no cap, full body read into memory,
  stopped only by the target timeout) so download-heavy targets can measure the
  true transfer time. The opt-out is rejected in the `defaults` block so it can
  never blanket the whole fleet. Motivation: the blackbox_exporter benchmark
  (`docs/benchmark-vs-blackbox.md`, Dimension C) showed the fixed 1 MiB cap
  truncates large pages (e.g. welt.de at 1.31 MiB). See `configuration.md` →
  HTTP Configuration → `max_body_bytes`.

---

### TLS Improvements

Planned:

- certificate chain inspection
- OCSP validation
- certificate SAN validation
- certificate expiration alerts
- weak cipher detection

---

### DNS Improvements

Planned:

- DNSSEC validation
- resolver comparison
- multiple resolver
- authoritative server checks

---

### Diagnostics API

Planned:

REST API:

```
GET /api/v1/probes/{target}
```

Provides:

- latest result
- execution phases
- detailed error information
- redirect chain
- TLS information

---

## Version 0.3 - Protocol Expansion

### Goal

Expand beyond web monitoring.

---

### Planned Protocols

#### Mail

- SMTP
- IMAP
- POP3

Checks:

- connection
- TLS
- banner
- authentication

---

#### Infrastructure

- LDAP
- SSH
- NTP
- MQTT
- gRPC

---

## Version 0.4 - Operational Features

### Goal

Make Sentinel easier to operate.

---

### Planned Features

Configuration

- configuration API
- dynamic target management
- Git-based configuration
- configuration versioning

---

### Scaling

Planned:

- stateless hash-based sharding via `--shard-index` / `--shard-count` flags.
  Every instance loads the *same* config but keeps only the targets whose name
  hashes to its shard, so N targets spread across M instances with each carrying
  ~N/M. Because Sentinel holds only current state, this needs **no coordination**
  (no leader election, no shared state) — Prometheus scrapes each shard and
  remains the single source of truth. This lowers per-instance render cost, RSS
  and probe CPU, and adds fault isolation (one instance failing loses only its
  shard). See `metrics.md` → *Operating at scale*.

  Trade-offs to weigh before building: changing `--shard-count` reshuffles most
  targets under plain hashing (brief probe gaps / series churn — consistent
  hashing would mitigate but adds complexity); overlapping or incomplete shard
  sets double-probe or silently drop targets; and each instance carries a fixed
  Go-runtime baseline, so sharding only pays off past a few thousand targets.
  Note that raising `scrape_interval` (probe cadence is decoupled from scrape)
  is the cheaper first lever for scrape-cost pressure and should be preferred
  until probe CPU/RAM on one machine is the actual limit.

  Relates to the distributed multi-agent / multi-location vision in Version 1.0.

---

### User Interface

Optional web interface:

Features:

- target overview
- current status
- latency graphs
- failure diagnostics
- redirect visualization
- certificate overview

---

## Version 1.0 - Synthetic Monitoring Platform

### Goal

A complete synthetic monitoring platform.

---

### Planned Features

Distributed Monitoring

Multiple Sentinel agents:

                 Central Prometheus
                      ^
                      |
        +-------------+-------------+
        |                           |
    Sentinel Agent A          Sentinel Agent B
    Europe                    US

---

### Multi-Location Checks

Detect:

- regional outages
- routing problems
- CDN issues
- DNS propagation problems

---

### Baseline Analysis

Instead of fixed thresholds:

```
Current TTFB:

350ms


Normal baseline:

50ms


Deviation:

+600%
```

Possible alerts:

- unusual latency
- unexpected behavior
- degradation trends

---

## Deferred / Optional

Explicitly pushed back and marked **optional**: not tied to any version and not
required for Sentinel to be fully useful. Revisit only when a concrete need
appears. (Distinct from *Out of Scope* below, which are hard non-goals.)

- **configuration templates** — reduce config duplication. Deferred: the flat
  `defaults` + `targets` model is adequate at the current scale, so the added
  complexity is not justified yet.
- **hot reload** (SIGHUP / config file watch) — apply config changes without a
  restart. Deferred: a rolling restart is acceptable for the current deployment
  model; low marginal value today.
- **HTTP/3 support** — probe over HTTP/3 / QUIC. Deferred: value is questionable
  right now — most monitored endpoints do not require QUIC-level probing and the
  standard-library HTTP/3 story is still maturing. Revisit if real demand shows.

---

## Out of Scope

The following are intentionally not primary goals:

### Full APM

Sentinel is not:

- tracing
- application profiling
- distributed tracing

---

### Log Management

Sentinel does not replace:

- Loki
- Elasticsearch
- Splunk

---

### Long Term Storage

Prometheus and compatible systems remain responsible for history.

---

## Design Decisions

### Why Sentinel instead of Blackbox Exporter?

Sentinel solves different problems.

Blackbox Exporter:

```
Prometheus scrape
       |
Execute probe
       |
Return result
```

Sentinel:

```
Continuous scheduler
       |
Execute probes
       |
Maintain state
       |
Expose metrics
```

Advantages:

- predictable execution
- better performance
- bounded, controllable concurrency
- richer diagnostics (per-phase timing)
- easier scaling

---

## Why Go?

Go was selected because it provides:

### Networking

Native support for:

- HTTP
- TLS
- DNS
- TCP
- concurrency

---

### Deployment

A Sentinel installation should be:

```
single binary
+
configuration file
```

No runtime dependencies.

---

### Performance

Go provides:

- lightweight goroutines
- efficient networking
- low memory usage

---

## Why YAML Configuration?

YAML was selected because:

- operators understand it
- it works well with Git
- it integrates with automation workflows

Possible future additions:

- JSON API
- Kubernetes resources
- service discovery

---

## Why Prometheus Pull Model?

Sentinel does not push metrics.

Reasons:

- Prometheus remains the source of truth
- standard scraping model
- simpler operation
- better compatibility

---

## Why Not Store History Internally?

Sentinel stores only current state.

Historical analysis belongs to:

- Prometheus
- Thanos
- VictoriaMetrics
- Cortex
- Mimir

This keeps Sentinel:

- simple
- fast
- reliable

---

## Architecture Principles

Sentinel follows:

Separation of concerns

Execution:

```
Probe
```

Validation:
```
Validator
```
Storage:

```
Result Store
```

Presentation:

```
Metrics/API
```

---

### Stable Interfaces

New protocols should be added without modifying:

- scheduler
- metrics layer
- configuration engine

---

## Long Term Vision

Sentinel should become a modern synthetic monitoring engine focused on:

- availability
- performance
- diagnostics
- operational simplicity

The key difference is:

A failed check is not the result.

A failed check is the beginning of an investigation.
