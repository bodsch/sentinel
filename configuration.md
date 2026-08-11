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

> **Version scope:** This document specifies the full configuration surface. **Version 0.2**
> implements a `defaults` + `targets` layout (no templates), a fixed label set, a single total
> `timeout`, and three protocols: **HTTP** (methods GET/HEAD/POST/PUT/PATCH/DELETE, request body,
> custom headers, Basic/Bearer auth, per-target `max_body_bytes`), **DNS** (A/AAAA/MX/TXT), and
> **TCP** (connect + `banner_regex`). Response validators are status / body_regex / headers /
> **JSONPath** (`expect.json`). Sections marked **(0.2+ / planned)** below — templates, retry,
> per-target proxy, per-phase timeouts, **XPath**, hot reload, and the standalone `icmp`/`tls`/
> `network` blocks — are not yet implemented. Config is loaded once at startup; there is no hot
> reload yet.

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
| `--log-level` | override log level (default `info`): `debug`, `info`, `warn`, `error` |
| `--log-format` | log output format (default `json`): `json` or `text` |
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

Example:

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

> **Note:** `retries` (see Retry Configuration) is not implemented yet and is
> rejected as an unknown field. There is no `validate_tls` field either: TLS is
> always inspected for HTTPS targets (expiry, hostname, remaining days) — see the
> TLS section. Unknown fields fail validation, so keep example configs to the
> fields your version supports.

---

## Templates (0.2+)

> Not implemented yet. Currently only `defaults` + `targets` exist, with a trivial merge rule
> (a target value wins over the default, otherwise the default applies — no deep merge). Templates,
> with their nested merge semantics, are a later feature.

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
Only tags from a **fixed allowed set** become Prometheus labels: `environment`, `location`,
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
      method: GET         # GET, HEAD, POST, PUT, PATCH or DELETE
      follow_redirects: true
      max_redirects: 10
      max_body_bytes: 1048576
```

### `max_body_bytes`

Caps how many response body bytes the probe reads. It bounds memory and is a
denial-of-service safeguard. It follows the normal merge rule, so it can be set
in `defaults.http` and **overridden per target**:

```
defaults:
  http:
    max_body_bytes: 1048576   # 1 MiB default for every target

targets:
  # Large page: raise the cap so the full download time is measured.
  - name: media-heavy
    http:
      url: https://example.org/large
      max_body_bytes: 8388608   # 8 MiB

  # Opt out entirely: read the full body, bounded only by the target timeout.
  # Use only for trusted targets — this removes the DoS safeguard.
  - name: full-transfer
    http:
      url: https://example.org/report
      max_body_bytes: 0         # 0 = no cap
```

Rules:

- **unset** → inherits `defaults.http.max_body_bytes`, else the built-in 1 MiB.
- **positive** → cap in bytes; body beyond the cap is not read (so `download`
  timing reflects only the bytes read, and a `body_regex` cannot match past it).
- **0** → no cap; the full body is read into memory, stopped only by the
  per-target `timeout`. The resident cost is then bounded by *timeout ×
  bandwidth* of RAM — not by any byte limit — so a large or hostile server can
  make the probe consume substantial memory and OOM-kill the process. It trades
  the DoS safeguard for accuracy; use it only on trusted targets.
  **Only valid per target** — `max_body_bytes: 0` in the `defaults` block is
  rejected, so the opt-out can never blanket the whole fleet from one line.
- **negative** → rejected at validation.

### Method and request body

`http.method` accepts `GET`, `HEAD`, `POST`, `PUT`, `PATCH` or `DELETE`
(case-insensitive). `http.body` sends a request body with the initial request;
set its `Content-Type` via `headers`:

```
targets:
  - name: ingest
    http:
      url: https://api.example.org/ingest
      method: POST
      headers:
        Content-Type: application/json
      body: |
        {"probe": "sentinel", "ping": true}
      expect:
        status: 202
```

- `http.body` is rejected with `GET` or `HEAD` (a body there is almost always a
  mistake).
- If the probe follows a redirect, it is followed as a **bodyless GET** — the
  method and body apply to the initial request only. This matches common client
  behaviour for 301/302/303 and avoids re-sending the body (duplicate
  side-effects, cross-origin leaks). Set `follow_redirects: false` if a target
  needs the method preserved across a redirect.

### Request headers and authentication

`http.headers` sets **request** headers (distinct from `http.expect.headers`,
which validate the *response*). A `Host` key sets the request host (useful for
virtual hosts). A custom `User-Agent` overrides Sentinel's default.

Authentication adds an `Authorization` header via one of two shorthands:

```
targets:
  - name: api
    http:
      url: https://api.example.org/health
      headers:
        X-Api-Key: "abc123"
        Accept: application/json
      basic_auth:
        username: monitor
        password: "s3cret"

  - name: api-bearer
    http:
      url: https://api.example.org/status
      bearer_token: "eyJhbGciOi..."
```

Rules:

- `basic_auth` requires a `username`; the `password` may be empty.
- **At most one** of `basic_auth`, `bearer_token`, or an explicit `Authorization`
  entry in `headers` may be set — they all target the same header.
- **Security:** request headers and credentials are sent **only to the target's
  own host**. If the probe follows a redirect to a *different* host, they are
  dropped on that hop, so credentials never leak to a third party.
- **Secrets** are given inline here. Protect the config file's permissions
  accordingly. Reading secrets from a file or environment variable
  (`password_file` / `bearer_token_file`) is a planned enhancement — see
  `Roadmap.md`.

### TLS verification

For HTTPS targets Sentinel **verifies the certificate chain against the system
roots by default** — an expired, wrong-host, or untrusted (self-signed /
unknown-CA) certificate fails the probe. Expiry and remaining-days are always
reported as metrics, even on failure.

```
targets:
  # Internal endpoint with a private CA: verify against that CA (secure).
  - name: internal-api
    http:
      url: https://api.internal.example
      tls:
        ca_file: /etc/sentinel/internal-ca.pem

  # Self-signed endpoint you cannot verify: accept any certificate.
  - name: appliance
    http:
      url: https://192.0.2.10/
      tls:
        insecure_skip_verify: true
```

- **default** (no `tls` block) → verify against the system roots.
- `ca_file` → verify against a custom PEM bundle instead (for internal CAs). The
  file is read at startup; a missing/invalid file is a startup error.
- `insecure_skip_verify: true` → accept **any** certificate (chain trust is not
  required); expiry and hostname are still reported and
  `sentinel_tls_certificate_valid` still reflects the *real* validity, so you can
  alert on an untrusted cert even while accepting it. Use only for endpoints you
  cannot otherwise verify. **Mutually exclusive with `ca_file`.**
- **Security note:** without verification a MITM presenting a certificate with
  the right hostname would be accepted (and any configured credentials sent to
  it), so `insecure_skip_verify` genuinely lowers security — prefer `ca_file`.

---

### TLS expectations

Beyond verification, a target can declare **operational** expectations about its
TLS connection. They are entirely opt-in: without a `tls.expect` block nothing
new can fail a probe, and the certificate diagnostics
(`metrics.md` → *TLS Metrics*) are exported either way.

```
targets:
  - name: homepage
    http:
      url: https://example.org
      tls:
        expect:
          min_days_remaining: 21           # renew window, spans the whole chain
          min_version: "1.3"               # "1.2" or "1.3"
          require_ocsp_stapling: true      # a stapled response saying "good"
          issuer_regex: "Let's Encrypt"    # pin the issuing CA
```

| Field | Effect when breached |
|---|---|
| `min_days_remaining` | `reason="certificate_expiring"` |
| `min_version` | `reason="tls_policy_violation"` |
| `require_ocsp_stapling` | `reason="tls_policy_violation"` |
| `issuer_regex` | `reason="tls_policy_violation"` |

- `min_days_remaining` covers the **whole chain**, so an intermediate or root
  expiring before the leaf trips it too. `certificate_expiring` is deliberately a
  separate reason from `certificate_expired`: the service still works, and the
  response is to renew, not to page.
- `min_version` accepts only `1.2` and `1.3`. A lower bound would be a no-op
  Sentinel could not honour — the probe transport never offers below TLS 1.2 — and
  a configuration option that silently does nothing is worse than none.
- `require_ocsp_stapling` demands a stapled response whose status is `good`. A
  missing, unparsable, unknown or **revoked** staple is a breach. Note that many
  large sites do not staple at all (Let's Encrypt retired OCSP entirely), so
  enable this only where you know the server does.
- `issuer_regex` is matched against the issuing CA's common name. It makes an
  unannounced CA migration fail loudly — and with it a certificate swapped by
  anyone able to obtain one from a different public CA.

**When they are evaluated.** After the handshake succeeds *and* after the response
validators. The security-critical checks (untrusted chain, expired certificate,
hostname mismatch) still abort the handshake before any request — and therefore
any credentials — is sent. A policy breach is a different thing: the connection is
already cryptographically sound, so aborting it mid-handshake would only discard
the status code, the phase timings and the very TLS diagnostics needed to judge
the breach. Running after the validators also keeps a genuine functional failure
(wrong status, bad body) ranked above a compliance warning.

**Scope.** Like `ca_file` and `insecure_skip_verify`, expectations apply only to
the target's own origin (scheme + host + port). A redirect to a third-party host
is never judged against them.

**Mutually exclusive with `insecure_skip_verify`** — expectations describe a
verified connection, and evaluating them against a certificate nobody vouched for
would read as a guarantee the configuration cannot give.

Not covered: enumerating a server's *supported* cipher suites. Sentinel offers
only TLS 1.2+ and Go's secure suites, so a weak suite is never negotiated and a
`forbid_weak_ciphers` switch would be a no-op. Probing what a server would
additionally accept needs several deliberately downgraded handshakes and belongs
to the planned standalone `tls:` probe.

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

## JSON Validation (0.2)

`http.expect.json` is a list of JSONPath assertions on a JSON response body
(standard `$`-rooted JSONPath, via `github.com/ohler55/ojg`). Each entry has a
`path` that must resolve; when it also sets `equals`, the resolved **scalar**
value (compared as a string) must equal it. Omitting `equals` is an
existence-only check. All assertions must pass.

```
http:
  url: https://api.example.org/status
  expect:
    json:
      - path: "$.status"
        equals: "healthy"     # scalar equality (string, number, or bool)
      - path: "$.version.major"
        equals: "2"           # numbers compared by their text form
      - path: "$.components"   # existence only (path must resolve)
```

- The body must parse as JSON (a non-JSON body, trailing data after the JSON, or
  a body truncated by `max_body_bytes` all fail). For large JSON responses, raise
  `max_body_bytes` (or set it to `0`) so the whole document is read.
- Numbers compare **numerically**: `equals: "200"` matches `200`, `200.0` and
  `2e2`. Strings, bools and `null` compare by text (`equals: "null"` matches a
  JSON null).
- `equals` compares scalars only. A path resolving to an array or object with
  `equals` set fails; use it without `equals` for an existence check.
- A path that matches **several** nodes (via a wildcard or filter, e.g.
  `$.items[*].status`) requires **every** matched value to satisfy `equals`;
  existence needs at least one match.
- `expect.json` cannot be used with method `HEAD` (no response body). An invalid
  `path` is rejected at config validation.

---

## XPath Validation (0.2+)

> Not implemented yet (unlike JSON validation above, which is).

Example:
```
http:
  expect:
    xpath:
      "//title": "Dashboard"
```
---

## DNS Configuration (0.2)

A DNS target queries a resolver for a record and validates the response. A target
carries exactly one protocol block, so a target is either `http` or `dns`.

```
targets:
  - name: dns-check
    interval: 30s
    dns:
      server: 1.1.1.1          # host or host:port (default port 53)
      query: example.org       # name to look up
      type: A                  # A, AAAA, MX or TXT (default A, case-insensitive)
      expected:                # optional; at least one answer must match
        - 93.184.216.34
```

Supported record types (0.2): **A, AAAA, MX, TXT**. (CNAME/SRV and DNSSEC
validation remain future work.)

Behaviour:

- The query uses UDP with EDNS0 (4096-byte buffer) and automatically retries over
  TCP if the response is truncated, so large answer sets are handled correctly.
- Success requires an RCODE of NOERROR. A non-NOERROR code (e.g. NXDOMAIN) fails
  with reason `dns_error`; the code is exposed as `sentinel_dns_response_code`.
- Without `expected`, a NOERROR response is a success even with zero answers —
  use `sentinel_dns_answer_count == 0` to alert on "did not resolve".
- With `expected`, at least one answer must match. Matching is type-aware: IPs
  compare numerically (A/AAAA), MX hostnames compare case-insensitively, TXT
  compares exactly.

---

## TCP Configuration

A TCP target checks that a connection to `address` (`host:port`) can be
established, and optionally validates a banner the server sends on connect. The
connect time is exposed as `sentinel_tcp_connect_duration_seconds`; availability
is the generic `sentinel_probe_success`.

Connection-only check:

```
targets:
  - name: postgres
    timeout: 5s          # target-level total timeout
    tcp:
      address: db.example.org:5432
```

With banner validation (e.g. an SSH or SMTP greeting):

```
targets:
  - name: ssh
    tcp:
      address: ssh.example.org:22
      expect:
        banner_regex:
          - "^SSH-2.0"
```

- `tcp.address` is required and must be `host:port` with a numeric port in
  1-65535.
- `expect.banner_regex` patterns must **all** match the banner. When set, the
  probe reads a banner (up to 4 KiB) after connecting, bounded by the target
  timeout; if none arrives the check fails. When omitted, only the connection is
  checked (no read).

---

## ICMP Configuration (planned)

> Not implemented. An `icmp` protocol block does not exist yet and is rejected as
> an unknown field. Planned shape:

```
icmp:
  host: router.example.org
  count: 5
  timeout: 3s
```

Planned metrics: packet loss, latency, jitter.

---

## TLS Configuration (planned)

> Not implemented **as a standalone protocol block**. For HTTPS targets TLS is
> already inspected in depth — chain, negotiated version and cipher, certificate
> identity, key strength and OCSP stapling (see *TLS verification* and *TLS
> expectations* above, and `metrics.md` → *TLS Metrics*). What is missing is a
> `tls:` target type for endpoints that are not HTTP: LDAPS (636), SMTPS (465),
> MQTT over TLS (8883), or any bare TLS port. A top-level `tls:` block is
> rejected as an unknown field. Planned shape:

```
tls:
  host: ldap.example.org
  port: 636
```

It would reuse the existing `internal/tlsdiag` inspection and therefore emit the
identical `sentinel_tls_*` series — the collector is already
protocol-independent. Chain validation and a minimum-remaining-days threshold are
not part of that shape because they exist today as `tls.expect`
(`min_days_remaining`) rather than as protocol-block options.

That probe is also where enumerating a server's *supported* TLS versions and
cipher suites belongs: it needs several deliberately downgraded handshakes, which
a probe that also has to measure request latency must not do.

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

> Not implemented yet. A probe run is a single attempt. Transient failures are meant to be
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

Today a target has a **single total `timeout`**, applied as one deadline over the whole probe run
(including all redirect hops). If it fires, the failure reason is `timeout` and the log carries the
`phase` reached (from HTTP tracing), so you still see roughly where it hung.

```
timeout: 10s
```

### Per-phase timeouts (0.2+)

> Not implemented yet. Fine-grained per-phase deadlines require reaching into the transport's
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

Today Sentinel honours the standard `HTTP_PROXY` / `HTTPS_PROXY` environment variables
(`http.ProxyFromEnvironment`), which is often required in corporate networks.

### Per-target proxy (0.2+)

> Not implemented yet.

```
http:
  proxy:
    url: http://proxy.example.org:3128
```
---

## IPv4 / IPv6 Selection (planned)

> Not implemented. There is no `network` block yet; it is rejected as an unknown
> field. Planned shape:

```
network:
  ip_version: ipv4    # auto | ipv4 | ipv6
```

---

## Configuration Validation

Before activation Sentinel validates (run it explicitly with `--validate`):

- syntax and schema, rejecting unknown fields
- exactly one protocol block per target (`http` / `dns` / `tcp`)
- duplicate target names, non-positive intervals/timeouts
- HTTP: method in the allowed set; `expect.status` in 100–599; non-empty
  `body_regex` patterns that compile; a URL with a host and **no** embedded
  userinfo credentials; a valid JSONPath for each `expect.json` entry; auth
  mutual-exclusivity; `max_body_bytes` not negative (and `0` only per target)
- DNS: supported record type; non-empty `expected` values
- TCP: `address` is `host:port` with a numeric port in 1–65535; banner regexes
  compile

Example:

```
Configuration validation failed:

target "api"

HTTP validator:

unknown field "status_codee"
```

---

## Hot Reload (only an idea, not planned before 0.8+)

> Not implemented yet. Config is loaded once at startup; to apply changes, restart the process
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

A complete, valid example that passes `--validate`:

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
> test — use it as the authoritative, always-current example. It exercises HTTP,
> DNS and TCP targets; only templates remain unsupported and are rejected by the
> loader.

---

## Design Goals

The Sentinel configuration format intentionally favors:

- clarity over compactness
- explicit behavior
- safe defaults
- automation friendliness

The configuration should be understandable without reading implementation details.
