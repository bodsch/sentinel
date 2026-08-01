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

sentinel_tls_certificate_expiry_timestamp
```

---

## Common Labels

Labels come from a **fixed, validated set** — this exact list. Arbitrary user tags are *not* turned
into labels in 0.1: a `tags:` key outside this set is rejected at config validation time, which
protects against accidental cardinality explosions. Free-form tags-as-labels (with sanitizing and
governance) are a later feature.

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

Total execution time.

```
sentinel_probe_duration_seconds
```

Type:

```
Gauge
```

Example:

```
sentinel_probe_duration_seconds{
    target="homepage"
} 0.152
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
```

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

The first byte received after sending the request.

```
sentinel_http_ttfb_seconds

```
This is one of the most important application performance indicators.

Example:

```
sentinel_http_ttfb_seconds{
    target="api"
} 0.084
```

---

### Response Download

```
sentinel_http_download_duration_seconds
```

---

### Response Size

```
sentinel_http_response_size_bytes
```

---

### Transfer Rate

```
sentinel_http_transfer_rate_bytes_per_second
```

---

## Redirect Metrics

### Redirect Count

```
sentinel_http_redirects_total
```

---

### Redirect Loop

```
sentinel_http_redirect_loop
```

Values:

```
1 = loop detected

0 = normal
```

---

### Redirect Limit Exceeded

```
sentinel_http_redirect_limit_exceeded
```

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
1 = valid

0 = invalid
```

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

---

### TCP Availability

```
sentinel_tcp_available
```

Values:

```
1 = reachable

0 = unreachable
```

---

## Histograms

> **Version note:** Histograms are a **0.2** feature. Version 0.1 exposes the current-value state
> gauges above (read live at scrape time). Histograms accumulate *observations* and must be fed at
> probe time via `.Observe()` — a different lifecycle from the scrape-time state collector — so they
> are introduced alongside that mechanism in 0.2.

For latency analysis Sentinel should expose histograms.

Example:

```
sentinel_http_ttfb_seconds_bucket
```

Recommended buckets:

```
0.005
0.01
0.025
0.05
0.1
0.25
0.5
1
2.5
5
10
```

This allows queries like:

```
histogram_quantile(
  0.95,
  rate(
    sentinel_http_ttfb_seconds_bucket[5m]
  )
)
```

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
sentinel_http_redirect_loop == 1
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
