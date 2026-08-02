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

- histogram support (latency distributions, fed at probe time)
- in-probe retry with retry metrics
- configuration templates and hot reload

---

### HTTP Improvements

Planned:

- HTTP/2 optimization
- HTTP/3 support
- custom request headers
- request body support
- authentication support
- JSONPath validation
- XPath validation
- body size validation
- compression analysis
- configurable `max_body_bytes` cap (per-target override; today a fixed 1 MiB
  global default). Motivation: the blackbox_exporter benchmark
  (`docs/benchmark-vs-blackbox.md`, Dimension C) showed the fixed cap truncates
  large pages (e.g. welt.de at 1.31 MiB), so Sentinel's `download`/`total`
  timings are not comparable to a full-body probe on download-heavy targets.
  A per-target cap (raise where the full transfer time matters, keep low as a
  DoS safeguard elsewhere) restores comparable totals without losing the guard.

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
