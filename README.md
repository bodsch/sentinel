# Sentinel

High Performance Synthetic Monitoring Engine for Prometheus

Sentinel is a modern synthetic monitoring daemon designed for on-premises environments.

It performs active availability, performance, and protocol checks and exposes detailed metrics through a Prometheus-compatible endpoint.

The goal of Sentinel is not only to answer:

«"Is this service available?"»

but also:

«"Why is this service slow or unavailable?"»

Sentinel focuses on detailed diagnostics, low overhead, and extensibility.

---

## Scope of this document

This README describes the **full product vision**. The current milestone, **version 0.2**, builds on
the complete runtime skeleton (configuration → scheduler → probe → result store → `/metrics`) and
already ships:

- **HTTP/HTTPS** probes with full phase timing (methods GET/HEAD/POST/PUT/PATCH/DELETE, request body,
  custom headers, Basic/Bearer auth, per-target body-size cap, redirect handling, TLS diagnostics)
- a **DNS** probe (A/AAAA/MX/TXT) and a **TCP** probe (connection check + optional banner validation)
- response validators: status, body regex, header match, and **JSONPath** (`expect.json`)
- latency **histograms** fed at probe time, plus per-phase gauges and `go_*`/`process_*` runtime metrics

Still planned: ICMP and other protocols, XPath validation, templates, hot reload, a debug API, and
distributed agents. See `Roadmap.md` for the version breakdown.

---

## Motivation

Prometheus is widely used for infrastructure monitoring. For synthetic monitoring, many installations
use the Prometheus Blackbox Exporter.

While the Blackbox Exporter is a valuable project, large-scale installations often encounter limitations:

- Probe execution happens during Prometheus scrapes.
- Every scrape triggers a complete probe lifecycle.
- Connection reuse is limited.
- DNS resolution is repeatedly performed.
- Configuration becomes complex with many targets.
- Diagnostic information is limited.
- Failed probes often provide only a binary success/failure result.

Sentinel takes a different architectural approach.

Instead of executing checks on demand, Sentinel continuously executes monitoring tasks and exposes the
current state through Prometheus metrics.

---

## Design Philosophy

Sentinel follows these principles:

### Continuous monitoring

Checks run independently from Prometheus scraping.

Prometheus only collects already calculated results.

### Detailed diagnostics

A failed check should provide information about the failure location.

Example:

```
DNS:          5ms
TCP Connect:  12ms
TLS:          35ms
TTFB:         850ms
Download:     5ms
```

This immediately identifies backend latency instead of only reporting an unavailable service.

### Low overhead

Sentinel uses:

- bounded worker concurrency (semaphore-limited execution)
- asynchronous scheduling decoupled from Prometheus scrapes
- efficient Go concurrency

Note on connections: for accurate diagnostics, monitoring probes deliberately use a
**fresh connection per run** rather than pooling/reusing connections. A reused connection
skips the DNS, TCP, and TLS phases entirely, which would make the per-phase timing metrics
inconsistent (sometimes present, sometimes zero). Since exposing those phases is the whole
point, connection reuse is intentionally *not* used for probes. Optional per-target reuse may
be added later for callers who prefer throughput over phase visibility.

### Extensible architecture

New protocols and validators can be added without changing the core engine.

---

## Features

### HTTP / HTTPS Monitoring

Supported features:

- methods GET / HEAD / POST / PUT / PATCH / DELETE
- request body (`http.body`) and custom request headers (`http.headers`)
- Basic auth (`http.basic_auth`) and bearer token (`http.bearer_token`)
- per-target response body-size cap (`http.max_body_bytes`, `0` = uncapped)
- status code validation
- header validation
- body regex validation
- JSONPath validation (`http.expect.json`)
- redirect tracking, loop detection, HTTPS→HTTP downgrade detection
- TLS certificate diagnostics (expiry, hostname, remaining days)

Planned: HTTP/2 tuning, HTTP/3, XPath validation, compression analysis.

Measured phases:

```
DNS lookup
    |
TCP connection
    |
TLS handshake
    |
HTTP request
    |
Time To First Byte
    |
Response download
```

---

## Redirect Monitoring

Redirects are treated as first-class monitoring events.

Sentinel detects:

- redirect loops
- excessive redirect chains
- invalid redirect targets
- HTTP downgrade redirects
- unexpected domain changes

Example:

```
http://example.org

    301

https://example.org

    302

https://www.example.org

    301

https://example.org

    LOOP DETECTED
```

The complete redirect chain is available through diagnostics.

---

## Performance Monitoring

Sentinel measures:

- DNS latency
- TCP connection latency
- TLS handshake latency
- Time To First Byte
- complete download duration

Example metrics (per-phase gauges; `sentinel_http_ttfb_seconds` and
`sentinel_probe_duration_seconds` are **histograms**, fed at probe time):

```
sentinel_http_dns_duration_seconds

sentinel_http_tcp_connect_duration_seconds

sentinel_http_tls_handshake_duration_seconds

sentinel_http_ttfb_seconds            # histogram (_bucket/_sum/_count)

sentinel_http_download_duration_seconds
```

See `metrics.md` for the full metric catalogue (probe state, TLS certificate,
DNS, TCP, `sentinel_scrape_duration_seconds`, `sentinel_build_info`, and the
`go_*`/`process_*` runtime collectors).

---

## Supported Protocols

### Implemented

- HTTP / HTTPS
- DNS (A, AAAA, MX, TXT)
- TCP (connection check + optional `banner_regex` validation)

### Planned

- ICMP
- SMTP
- IMAP
- POP3
- LDAP
- MQTT
- SSH
- NTP
- gRPC

---

Architecture Overview

                  +----------------+
                  | Configuration |
                  +-------+--------+
                          |
                          v
                  +---------------+
                  |   Scheduler   |
                  +-------+-------+
                          |
                          v
                  +---------------+
                  | Worker Pool   |
                  +-------+-------+
                          |
        +-----------------+----------------+
        |                 |                |
        v                 v                v
     HTTP Probe       DNS Probe       TCP Probe
                          |
                          v
                     Validation Pipeline
                          |
                          v
                   Metrics Collector
                          |
                          v
                   /metrics Endpoint
                          |
                          v
                      Prometheus

---

## Configuration Example

```yaml
targets:
  - name: homepage
    interval: 30s
    http:
      url: https://example.org
      expect:
        status: 200
        body_regex: "Welcome"
  - name: smtp-server
    interval: 60s
    tcp:
      address: mail.example.org:25
      expect:
        banner_regex:
          - "ESMTP"
  - name: dns-check
    interval: 30s
    dns:
      server: 1.1.1.1
      query: example.org
      type: A
```

---

## Prometheus Integration

Sentinel serves three endpoints (default `:8080`):

```
GET /metrics    Prometheus metrics
GET /healthz    liveness (always 200 while running)
GET /readyz     readiness (200 once started, else 503)
```

CLI flags: `-config`, `-validate` (load, validate, and exit), `-listen`,
`-log-level`, `-log-format`, `-version`.

Example:
```
sentinel_probe_success{target="homepage"} 1

sentinel_http_ttfb_seconds_bucket{target="homepage",le="0.1"} 42
```

---

## Future (maybe) Improvements

Planned improvements:

- REST API
- Web UI
- live probe execution
- dynamic configuration reload
- templates
- target inheritance
- tagging
- multi-location probes
- distributed agents
- baseline comparison
- anomaly detection

---

## Technology Choice

Sentinel is implemented in Go.

Reasons:

- excellent concurrency model
- low memory usage
- native networking support
- simple deployment
- static binaries
- excellent Prometheus ecosystem integration

---

## Project Vision

Sentinel aims to become a modern synthetic monitoring platform for environments where reliability, performance visibility, and operational control are more important than simple availability checks.

The primary goal is not detecting that something failed.

The primary goal is explaining why it failed.
