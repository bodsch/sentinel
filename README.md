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

- connection pooling
- reusable HTTP transports
- configurable worker pools
- asynchronous scheduling
- efficient Go concurrency

### Extensible architecture

New protocols and validators can be added without changing the core engine.

---

## Features

### HTTP / HTTPS Monitoring

Supported features:

- HTTP/1.1
- HTTP/2
- HTTP/3 (planned)
- status code validation
- header validation
- body validation
- regex checks
- JSONPath checks
- XPath checks
- redirect tracking
- redirect loop detection
- TLS validation

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
- transferred bytes
- transfer rate

Example metrics:

```
sentinel_http_dns_duration_seconds

sentinel_http_tcp_connect_duration_seconds

sentinel_http_tls_duration_seconds

sentinel_http_ttfb_seconds

sentinel_http_download_duration_seconds
```

---

## Supported Protocols

### Version 0.1

- HTTP
- HTTPS
- TCP
- DNS
- ICMP

### Planned

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
        banner: "ESMTP"


  - name: dns-check

    interval: 30s

    dns:
      server: 1.1.1.1
      query: example.org
      type: A
```

---

## Prometheus Integration

Sentinel exposes:

```
GET /metrics
```
Example:
```
sentinel_probe_success{target="homepage"} 1

sentinel_http_ttfb_seconds{
    target="homepage"
} 0.085
```

---

## Future Features

Planned improvements:

- REST API
- Web UI
- live probe execution
- configuration validation
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
