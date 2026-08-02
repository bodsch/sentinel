# Sentinel Architecture

## Overview

Sentinel is designed as an active synthetic monitoring engine.

Unlike traditional Prometheus exporters, Sentinel does not execute checks when Prometheus scrapes metrics. Instead, it continuously executes monitoring tasks and maintains the current state internally.

Prometheus only retrieves already calculated results.

The architecture is optimized for:

- predictable execution times
- high concurrency
- low resource usage
- detailed diagnostics
- extensibility

> **Version scope:** This document describes the target architecture. Version 0.1 implements the
> HTTP/HTTPS path end-to-end with the full skeleton below, sized for **hundreds of targets**.
> Components marked as future (hot reload, debug API, non-HTTP probes, histograms, a central
> scheduling queue) are deferred to later versions. See `Roadmap.md`.

---

## Component Overview

flowchart TD

```mermaid
    Config[Configuration Loader]

    Config --> Scheduler

    Scheduler --> Queue

    Queue --> WorkerPool

    WorkerPool --> ProbeEngine

    ProbeEngine --> HTTPProbe
    ProbeEngine --> DNSProbe
    ProbeEngine --> TCPProbe
    ProbeEngine --> ICMPProbe

    HTTPProbe --> Validators
    DNSProbe --> Validators
    TCPProbe --> Validators

    Validators --> ResultStore

    ResultStore --> MetricsExporter
    ResultStore --> DebugAPI

    MetricsExporter --> Prometheus
```

---

## Core Components

### Configuration Loader

The configuration layer is responsible for:

- loading YAML configuration
- validating configuration schema
- applying defaults
- handling configuration reloads
- managing target lifecycle

Configuration changes should not require a restart.

Future versions may support:

- filesystem watching
- REST-based configuration updates
- service discovery integration

---

## Scheduler

The scheduler determines when probes are executed.

Responsibilities:

- maintaining probe intervals
- distributing execution times
- preventing probe bursts
- handling missed executions
- applying jitter

Example:

Without jitter:

```
00:00:00  1000 checks start
00:01:00  1000 checks start
00:02:00  1000 checks start
```

With jitter:

```
00:00:00 - 00:00:20 distributed execution
00:01:00 - 00:01:20 distributed execution
00:02:00 - 00:02:20 distributed execution
```

This prevents unnecessary load spikes.

---

## Worker Pool

The worker pool bounds how many probes run concurrently.

Design goals:

- bounded concurrency
- predictable resource usage
- cancellation support
- timeout handling

**0.1 implementation — ticker + semaphore.** Due timing and execution are separated. Each target
runs its own goroutine with a `time.Ticker` (jittered by an initial offset) that signals when the
target is due. Actual execution passes through a semaphore (`chan struct{}` of capacity N), which
is the hard cap on *simultaneous* probes. This gives bounded concurrency without a full central
scheduling queue, which is deferred until a larger scale demands it.

```
Target A ticker ─┐
Target B ticker ─┤
Target C ticker ─┼──► semaphore (cap N) ──► probe execution
      ...        │
Target Z ticker ─┘
```

Overload rules: at most one in-flight probe per target (an overlapping tick is skipped, never
queued); a due probe waits briefly on the semaphore rather than being dropped immediately; every
skipped run is counted (`sentinel_probe_skipped_total`).

Workers never create uncontrolled goroutines.

---

## Probe Engine

The probe engine provides the common execution framework.

A probe consists of:

```
Prepare
   |
Execute
   |
Validate
   |
Collect Metrics
   |
Store Result
```

Every probe returns a normalized, **typed** result:

```go
type Result struct {
    Success       bool
    FailureReason FailureReason // stable enum, never a free-form string
    Duration      time.Duration // total, across all redirect hops
    Timings       Timings       // typed per-phase struct (DNS/TCP/TLS/TTFB/Download)
    Diagnostics   Diagnostics   // protocol-specific detail (e.g. HTTP redirect chain, TLS cert)
    Timestamp     time.Time
}
```

A previous draft modelled metrics as an untyped `map[string]float64`. That was dropped in favour
of a typed result: it gives compile-time safety and lets the rich HTTP diagnostics (redirect
chain, TLS certificate info, phase timings) live in properly typed fields instead of stringly
keyed floats.

Protocol-specific implementations only handle their own execution logic and populate their own
`Diagnostics` value.

---

## Probe Types

### HTTP Probe

The HTTP probe is the most feature-rich implementation.

Pipeline:

```
DNS Resolution
    |
TCP Connect
    |
TLS Handshake
    |
HTTP Request
    |
Redirect Handling
    |
Response Validation
    |
Metrics Collection
```

The probe uses:

- a fresh connection per run (no pooling — see below), so every DNS/TCP/TLS phase is measured
- HTTP tracing (`net/http/httptrace`) for per-phase timing
- configurable total timeout

---

## HTTP Timing Model

Sentinel separates HTTP timing into individual phases.

Example:

```
Total Duration

+-------------------------------+
| DNS                           |
+-------------------------------+
| TCP                           |
+-------------------------------+
| TLS                           |
+-------------------------------+
| Waiting for First Byte        |
+-------------------------------+
| Download                      |
+-------------------------------+
```

This allows identifying bottlenecks.

---

## HTTP Redirect Engine

Redirect handling is implemented separately from the HTTP client.

Responsibilities:

- track redirect chain
- detect loops
- enforce maximum redirects
- validate redirect targets

Internal model:

```
type RedirectStep struct {
    URL        string
    StatusCode int
}
```

Example:

```
RedirectChain:

[
  http://example.org,
  https://example.org,
  https://www.example.org
]
```

Loop detection compares normalized URLs.

---

## Validator Framework

Validators are independent components.

Examples:

```
StatusCodeValidator

HeaderValidator

BodyRegexValidator

JSONPathValidator

XPathValidator
```

A target can execute multiple validators.

Example:

```
expect:
  status: 200
  body_regex:
    - "healthy"
  headers:
    X-Service: "frontend"
```

---

## Result Store

The result store keeps the latest probe state.

Stored information:

- success state
- failure reason
- timings
- metadata
- diagnostic information

The store is optimized for:

- fast metric export
- concurrent reads
- low memory usage

Long-term history remains the responsibility of Prometheus.

---

## Metrics Exporter

The metrics exporter exposes:

```
/metrics
```

Responsibilities:

- serving `promhttp.Handler` over a dedicated (non-default) registry
- managing labels
- avoiding high-cardinality data

**Extensibility model — self-registering collectors.** The exporter itself knows nothing about
individual protocols. Each protocol package ships its own `prometheus.Collector` and registers it
with the shared registry. Adding a new protocol therefore requires *no* change to the exporter —
it just contributes another collector. The trade-off is a deliberate coupling of protocol packages
to `client_golang`, chosen because it is the idiomatic Prometheus approach.

**Hybrid metric lifecycle.** Two metric natures are handled differently:

- *State metrics* (probe success, current TTFB gauge, certificate remaining days, failure reason)
  are read **live at scrape time** by a custom collector that pulls from the result store. This
  keeps them always current with no in-process history and no staleness bookkeeping.
- *Distribution metrics* (histograms) are classic `prometheus.Histogram` objects that the probe
  feeds via `.Observe()` at run time. These arrive in 0.2; version 0.1 exposes state gauges only.

Large diagnostic information is not exposed as labels.

Example:

Good:

```
sentinel_probe_success{
 target="homepage"
}
```

Bad:

```
sentinel_probe_error{
 error_message="connection failed after 10 retries"
}
```

---

## Debug API

A future optional component.

Purpose:

Provide detailed troubleshooting information.

Example:

```
GET /api/v1/probes/homepage/latest
```

Response:

```
{
  "success": false,
  "phase": "tls",
  "error": "certificate expired",
  "duration": "124ms"
}
```

The Debug API contains information unsuitable for Prometheus labels.

---

## Concurrency Model

Sentinel uses Go's concurrency primitives.

Recommended structure:

```
Main Process
    |
    +-- Scheduler Goroutine
    |
    +-- Worker Pool
          |
          +-- Probe Execution Context
          |
          +-- Timeout Context
```

Every operation supports cancellation.

---

## Error Classification

Errors are classified into stable categories.

Example:

```
dns_error

tcp_timeout

tls_error

certificate_expired

redirect_loop

http_status_error

validation_failed
```

These categories are used for:

- metrics
- logging
- alerting

---

## Design Goals

The architecture intentionally separates:

- execution
- validation
- storage
- presentation

This allows new protocols and features without modifying the monitoring core.
