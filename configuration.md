# Sentinel Configuration Specification

## Overview

Sentinel uses a declarative YAML-based configuration format.

The configuration describes:

- what should be monitored
- how often checks are executed
- which protocol is used
- which validations are performed
- which defaults apply

The configuration is designed for:

- human readability
- large installations
- version control
- GitOps workflows
- automated generation

> **Version scope:** This document specifies the full configuration surface. **Version 0.1**
> implements only what the HTTP slice needs: `defaults` + `targets` (no templates), a fixed label
> set, a single total `timeout`, HTTP validators (status / body_regex / headers), and a bounded
> `max_body_bytes` (default 1 MB). Sections marked **(0.2+)** below — templates, retry, per-target
> proxy, per-phase timeouts, JSONPath/XPath, hot reload — are not yet implemented. Config is loaded
> once at startup; there is no hot reload in 0.1.

---

## CLI and validation

Sentinel is driven by a single config file and a small set of flags:

```
sentinel --config /etc/sentinel/config.yaml
```

| Flag | Purpose |
| :--- | :--- |
| `--config` | path to the config file (env `SENTINEL_CONFIG` also honoured) |
| `--validate` | load and fully validate the config, print any error, exit non-zero — do **not** start probes |
| `--version` | print version/commit/build date and exit |
| `--log-level` | override log level (default `info`) |
| `--listen` | override the HTTP listen address (default `:8080`) |

`--validate` is a dry-run intended for CI / GitOps: a config pull request can be checked before it
is deployed. On a normal start an invalid config is **fail-fast** — Sentinel refuses to start
rather than coming up with a partial configuration.

Validation checks structure, schema, and semantics only (syntax, duplicate target names, invalid
intervals, unknown fields, unsupported protocols, tags outside the allowed label set). It **never**
checks reachability: whether a target host resolves or responds is a *runtime measurement* — exactly
what Sentinel exists to observe — so an unreachable target is never a configuration error.

---

## Configuration Structure

The basic structure:

```
defaults:

templates:

targets:
```

Example:

```
defaults:
  interval: 60s
  timeout: 10s


targets:
  - name: homepage
    http:
      url: https://example.org
```

---

## Configuration Loading

Sentinel loads configuration in the following order:

```
Global Defaults
        |
Templates
        |
Target Configuration
        |
Runtime Overrides
```

Later values override previous values.

---

## Global Defaults

Defaults avoid repeating common settings.

Example (0.1 fields):

```
defaults:
  interval: 30s
  timeout: 10s
  http:
    method: GET
    follow_redirects: true
    max_redirects: 10
    max_body_bytes: 1048576
```

All targets inherit these settings.

> **Note:** `retries` (see Retry Configuration) is a 0.2+ field and is rejected
> by the 0.1 loader. There is no `validate_tls` field: in 0.1 TLS is always
> inspected for HTTPS targets (expiry, hostname, remaining days) — see the TLS
> section. Unknown fields fail validation, so keep example configs to the fields
> your version supports.

---

## Templates (0.2+)

> Not implemented in 0.1. In 0.1 only `defaults` + `targets` exist, with a trivial merge rule
> (a target value wins over the default, otherwise the default applies — no deep merge). Templates,
> with their nested merge semantics, arrive in 0.2.

Templates define reusable monitoring profiles.

Example:

```
templates:
  web-service:
    interval: 30s
    timeout: 5s
    http:
      expect:
        status: 200
```

Usage:

```
targets:
  - name: frontend
    template: web-service
    http:
      url: https://frontend.example.org
```

---

## Target Definition

A target represents one monitored endpoint.

Example:

```
targets:
  - name: api
    tags:
      service: backend
      environment: production
    interval: 15s
    http:
      url: https://api.example.org
      method: GET
```
---

## Target Metadata

Metadata is used for organization and filtering.

Example:
```
tags:
  service: payment
  environment: production
  location: datacenter-1
```
In 0.1 only tags from a **fixed allowed set** become Prometheus labels: `environment`, `location`,
`service` (plus the always-present `target` and `type`). A tag outside this set is **rejected at
config validation**, not silently ignored — this prevents accidental high-cardinality labels.
Free-form tags-as-labels, with sanitizing and governance, are a 0.2+ feature.

---

## HTTP Configuration

`timeout` is a **target-level** field (a single total timeout), not part of the
`http` block. The `http` block holds request/response settings:

```
targets:
  - name: homepage
    timeout: 10s          # target-level total timeout
    http:
      url: https://example.org
      method: GET         # GET or HEAD in 0.1
      follow_redirects: true
      max_redirects: 10
      max_body_bytes: 1048576
```

---

## HTTP Validation

Validators are explicitly defined.

Example:

```
http:
  expect:
    status: 200
    body_regex:
      - "Welcome"
    headers:
      Content-Type: "text/html"
```

---

## JSON Validation (0.2+)

> Not implemented in 0.1. The 0.1 HTTP validators are status code, body regex, and header match.
> JSONPath and XPath validation arrive in 0.2 via the same `Validator` interface.

Example:

```
http:
  url: https://api.example.org/status
  expect:
    json:
      "$.status": "healthy"
```

---

## XPath Validation (0.2+)

> Not implemented in 0.1 (see JSON Validation above).

Example:
```
http:
  expect:
    xpath:
      "//title": "Dashboard"
```
---

## DNS Configuration

Example:

```
dns:
  server: 1.1.1.1
  query: example.org
  type: A
  expected:
    - 93.184.216.34
```

Supported record types:

- A
- AAAA
- MX
- TXT
- CNAME
- SRV

Future:

- DNSSEC validation

---

## TCP Configuration

Example:
```
tcp:
  address: mail.example.org:25
  timeout: 5s
```
Optional banner validation:
```
tcp:
  expect:
    banner: "ESMTP"
```
---

## ICMP Configuration

Example:
```
icmp:
  host: router.example.org
  count: 5
  timeout: 3s
```
Metrics:

- packet loss
- latency
- jitter

---

## TLS Configuration

TLS checks can be standalone or attached to HTTPS.

Example:
```
tls:
  host: example.org
  port: 443
  validate_chain: true
  minimum_days_remaining: 30
```
---

## Scheduling

Each target can override intervals.

Example:
```
targets:
  - name: critical-api
    interval: 5s
  - name: documentation
    interval: 5m
```
---

## Retry Configuration (0.2+)

> Not implemented in 0.1. A probe run is a single attempt. Transient failures are meant to be
> damped in Prometheus alerting rules (`for:`), where alert tolerance already lives, rather than in
> the exporter. In-probe retry (with its own metrics and timeout interaction) is a 0.2 feature.

Transient failures should not immediately trigger alerts.

Example:
```
retry:
  attempts: 3
  delay: 5s
```
Execution:

```
Attempt 1
   |
Failure
   |
Wait 5 seconds
   |
Attempt 2
```

---

## Timeouts

In 0.1 a target has a **single total `timeout`**, applied as one deadline over the whole probe run
(including all redirect hops). If it fires, the failure reason is `timeout` and the log carries the
`phase` reached (from HTTP tracing), so you still see roughly where it hung.

```
timeout: 10s
```

### Per-phase timeouts (0.2+)

> Not implemented in 0.1. Fine-grained per-phase deadlines require reaching into the transport's
> dial and TLS-handshake machinery and defining how they compose with the total. Deferred to 0.2.

```
timeout:
  total: 10s
  dns: 2s
  connect: 3s
  tls: 5s
```
---

## Proxy Support

In 0.1 Sentinel honours the standard `HTTP_PROXY` / `HTTPS_PROXY` environment variables
(`http.ProxyFromEnvironment`), which is often required in corporate networks.

### Per-target proxy (0.2+)

> Not implemented in 0.1.

```
http:
  proxy:
    url: http://proxy.example.org:3128
```
---

## IPv4 / IPv6 Selection

Explicit protocol selection:

```
network:
  ip_version: ipv4
```

Allowed:

- auto
- ipv4
- ipv6

---

## Configuration Validation

Before activation Sentinel validates:

- syntax
- schema
- referenced templates
- duplicate target names
- invalid intervals
- unsupported protocols

Example:

```
Configuration validation failed:

target "api"

HTTP validator:

unknown field "status_codee"
```

---

## Hot Reload (only an idea, not planned before 0.8+)

> Not implemented in 0.1. Config is loaded once at startup; to apply changes, restart the process
> (cheap under systemd/Kubernetes). Diff-based hot reload is a later feature.

Configuration reload should not interrupt running probes.

Process:

```
New Configuration
        |
Validation
        |
Diff Calculation
        |
Apply Changes
        |
Continue Monitoring
```

Running probes continue with their existing configuration.

---

## Future Extensions

Possible future configuration sources:

- REST API
- Kubernetes ConfigMaps
- Consul
- etcd
- Git repositories
- Prometheus service discovery

---

## Complete Example

A complete, **0.1-valid** example that passes `--validate`:

```yaml
defaults:
  interval: 30s
  timeout: 10s
  http:
    method: GET
    follow_redirects: true
    max_redirects: 10
    max_body_bytes: 1048576

targets:

  - name: homepage
    tags:
      service: frontend
      environment: production
    http:
      url: https://example.org
      expect:
        status: 200

  - name: api-health
    interval: 15s
    tags:
      service: backend
      environment: production
    http:
      url: https://api.example.org/health
      expect:
        status: 200
        headers:
          Content-Type: application/json
```

> The repository ships `config.example.yaml`, which is kept valid by an automated
> test — use it as the authoritative, always-current example. The earlier
> template/TCP-based example was removed because templates and non-HTTP protocols
> are 0.2+ and are rejected by the 0.1 loader.

---

## Design Goals

The Sentinel configuration format intentionally favors:

- clarity over compactness
- explicit behavior
- safe defaults
- automation friendliness

The configuration should be understandable without reading implementation details.
