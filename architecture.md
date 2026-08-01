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

The worker pool executes probes concurrently.

Design goals:

- bounded concurrency
- predictable resource usage
- cancellation support
- timeout handling

Example:

```
Scheduler

    |
    v

Probe Queue

    |
    +---- Worker 1
    |
    +---- Worker 2
    |
    +---- Worker 3
```

Workers should never create uncontrolled goroutines.

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

Every probe returns a normalized result:

```
type ProbeResult struct {
    Success   bool
    Duration time.Duration
    Error    error
    Metrics  map[string]float64
}
```

Protocol-specific implementations only handle their own execution logic.

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

- shared HTTP transports
- connection pooling
- HTTP tracing
- configurable timeouts

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

- converting internal state into Prometheus metrics
- managing labels
- avoiding high-cardinality data

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
