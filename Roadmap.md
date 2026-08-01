# Sentinel Roadmap

## Project Status

Sentinel is currently in the design phase.

The roadmap focuses on building a stable monitoring foundation before adding advanced functionality.

The primary goal is a reliable synthetic monitoring engine with excellent Prometheus integration.

---

## Version 0.1 - Core Monitoring Engine

### Goal

Create a production-ready monitoring daemon capable of replacing common Blackbox Exporter use cases.

---

### Core Runtime

Implemented:

- Go application structure
- configuration loading
- configuration validation
- scheduler
- worker pool
- probe lifecycle management
- timeout handling
- graceful shutdown

---

### HTTP Monitoring

Implemented:

- HTTP/HTTPS checks
- HTTP GET requests
- status code validation
- TLS validation
- redirect handling
- redirect loop detection
- connection reuse
- HTTP timing instrumentation

Metrics:

- total duration
- DNS duration
- TCP duration
- TLS duration
- TTFB
- download duration

---

### DNS Monitoring

Implemented:

- A records
- AAAA records
- MX records
- TXT records
- response validation
- query timing

---

### TCP Monitoring

Implemented:

- TCP connection checks
- timeout handling
- banner validation

---

### ICMP Monitoring

Implemented:

- reachability checks
- latency measurement
- packet loss measurement

---

### Prometheus Integration

Implemented:

- `/metrics`
- stable metric naming
- label handling
- histogram support
- error classification

---

## Version 0.2 - Advanced Diagnostics

### Goal

Increase diagnostic capabilities.

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
- connection reuse
- richer diagnostics
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
