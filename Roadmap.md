# Sentinel Roadmap

## Project Status

**Versions 0.1 and 0.2 are implemented and shipped.** The runtime skeleton
(configuration → scheduler → probe → result store → `/metrics`) is complete, and
four protocols run end-to-end: HTTP/HTTPS (full phase timing, methods, body,
headers, auth, redirect handling, TLS chain verification), DNS (A/AAAA/MX/TXT/CNAME/SRV,
resolver comparison, a zone's nameservers checked for authority and SOA serial,
DNSSEC via the resolver's AD flag), TCP (connect + banner) and TLS (any endpoint
speaking TLS on connect — LDAPS, SMTPS, IMAPS, MQTT … — or after a STARTTLS
upgrade for SMTP, IMAP, POP3 and LDAP, with optional enumeration of the accepted
versions and cipher suites). Response validators cover status / body-regex /
header / JSONPath, latency histograms are fed at probe time, and the build ships
with security tooling (golangci-lint incl. gosec, govulncheck) and Forgejo CI /
release pipelines. Later versions (0.3+) below are still planned; items dropped during triage are
listed under *Declined*.

The roadmap focuses on building a stable monitoring foundation before adding advanced functionality.

The primary goal is a reliable synthetic monitoring engine with excellent Prometheus integration.

---

## Version 0.1 - Core Monitoring Engine (HTTP slice)

### Goal

Create a production-ready monitoring daemon for the **HTTP/HTTPS** use case, with the complete
runtime skeleton in place so further protocols slot in without reworking the core. Version 0.1 is a
deliberately narrow vertical slice — one protocol done end-to-end, not several done partially.

> Status: **shipped.** The list below is the 0.1 scope, all implemented; 0.2 (below) builds on it.

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
- TLS diagnostics: expiry, hostname match, remaining days (manual certificate
  inspection); extended in 0.2 to the full chain, negotiated version/cipher,
  certificate identity and OCSP stapling — see *TLS Improvements* below
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

> Status: **shipped.** Individual items below carry `(implemented)` / `Planned`
> markers; everything marked implemented is in the current build.

---

### DNS Monitoring

Implemented:

- A / AAAA / MX / TXT / CNAME / SRV records against a configurable resolver
- RCODE, answer-count and query-timing metrics
- optional expected-answer validation (type-aware matching)
- EDNS0 + automatic TCP fallback on truncation

Planned:

- ~~DNSSEC validation~~ **(implemented, resolver-trusting)**: `dns.dnssec`
  sends the DO bit and requires the AD flag from the resolver; a missing flag
  fails with the new reason `dnssec_unvalidated`, a bogus signature arrives as
  SERVFAIL (`dns_error`). The earliest RRSIG expiry over the queried type is
  exported, so a signer that stopped re-signing shows up before the zone
  breaks. Validating the chain to the root trust anchor inside Sentinel was
  considered and declined: it duplicates the validating resolver and adds
  trust-anchor maintenance.

---

### TCP Monitoring

Implemented:

- TCP connection checks (`tcp.address` = host:port) with connect-duration metric
  (`sentinel_tcp_connect_duration_seconds`)
- timeout handling (target timeout bounds connect + banner read)
- banner validation (`tcp.expect.banner_regex`, all-must-match)

Planned:

- query/response sequences (send a payload, expect a reply) beyond a
  server-first banner
- optional TLS on a TCP target. Today an endpoint that speaks TLS on connect is
  covered by the `tls:` block instead, which is the clearer split: `tcp:` answers
  "does it accept connections", `tls:` answers "is the certificate sound";
  STARTTLS ports are covered by `tls.starttls`.

---

### TLS Monitoring

Implemented:

- standalone `tls:` target for endpoints speaking TLS on connect (`tls.host`,
  `tls.port`), with DNS / connect / handshake phase timings
- the complete certificate, chain, version, cipher and OCSP diagnostics shared
  with the HTTPS path
- ALPN negotiation (`tls.alpn`) reported as `sentinel_tls_alpn_info`
- mutual TLS, SNI override and version cap shared with `http.tls`
- STARTTLS (`tls.starttls`: smtp, imap, pop3, ldap)
- supported-version / supported-cipher enumeration (`tls.enumerate`)

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
- ~~request body support~~ **(implemented)**: `http.method` now accepts
  GET/HEAD/POST/PUT/PATCH/DELETE and `http.body` sends a request body (set
  Content-Type via `headers`). A redirect is followed as a bodyless GET. See
  `configuration.md`.
- ~~authentication~~ **(implemented)**: `http.basic_auth` and `http.bearer_token`
  (mutually exclusive with each other and an explicit Authorization header),
  applied same-host-only for leak safety. ~~File-based secrets~~
  **(implemented)**: `basic_auth.password_file` / `bearer_token_file`, read once
  at startup; `--validate` does not open them, so a CI dry-run needs no access
  to the secrets. Environment-variable references were not added — a file covers
  systemd credentials and Kubernetes secrets alike.
- ~~JSONPath validation~~ **(implemented)**: `http.expect.json` — a list of
  `{path, equals}` JSONPath assertions on a JSON response body (existence and
  scalar equality), via `github.com/ohler55/ojg` (zero transitive deps). See
  `configuration.md`.
- XPath validation
- body size validation
- compression analysis
- ~~optional egress guard for redirects~~ **(implemented)**: opt-in
  `http.block_private_redirects` refuses a redirect to a different host whose
  resolved address is private/loopback/link-local (failure reason
  `redirect_blocked`). Enforced in the dialer on the address actually
  connected to, so DNS rebinding cannot bypass it; behind an HTTP proxy the
  hop's name is checked up front (best effort). Closes the low-severity
  security-audit finding (blind recon of internal hosts via an
  attacker-controlled redirect). A per-target host allow-list was not added —
  no concrete need yet.
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

- ~~certificate chain inspection~~ **(implemented)**: HTTPS targets now verify
  the chain against the system roots by default (untrusted/expired/wrong-host
  fails), with per-target `tls.ca_file` (custom CA) and `tls.insecure_skip_verify`
  (accept any cert; validity still reported honestly). Closed a MITM
  credential-leak found in the security audit. See `configuration.md` → *TLS
  verification*.
- ~~full chain diagnostics~~ **(implemented)**: the TLS inspection moved out of
  the HTTP package into `internal/tlsdiag`, which now reports the whole chain
  (`sentinel_tls_chain_earliest_expiry_timestamp_seconds`, `_earliest_remaining_days`,
  `_length`, `_verified`), the negotiated version and cipher
  (`sentinel_tls_version_info`, `sentinel_tls_cipher_info`), certificate identity
  and strength (`sentinel_tls_certificate_info`, `_key_bits`, `_san_count`,
  `_not_before_timestamp_seconds`, `_self_signed`) and `sentinel_http_ssl`.
  Motivation: the leaf-only metrics could not see an intermediate or root expiring
  before the leaf — an outage that arrives with no warning. The collector is
  protocol-independent, so a future `tls:` or TLS-enabled `tcp` probe gains the
  whole set for free. Verified against `blackbox_exporter 0.28.0`: for the same
  certificate the earliest-expiry values agree to the second, and serial and
  SHA-256 fingerprint match byte for byte.
- ~~OCSP validation~~ **(implemented, stapling only)**: the response the server
  staples is parsed and *verified* (signed by the certificate's issuer, referring
  to that certificate), reported via `sentinel_tls_ocsp_stapled`,
  `sentinel_tls_ocsp_info{status}` and `_next_update_timestamp_seconds`. Sentinel
  deliberately does **not** query an OCSP responder itself: that would add the
  responder's latency to the measurement, turn a responder outage into an apparent
  target failure, and disclose the monitored host list to the CA. Active querying
  stays open as a per-target opt-in if a concrete need appears.
- ~~certificate expiration alerts~~ **(implemented)**: opt-in
  `tls.expect.min_days_remaining` spanning the whole chain, with its own failure
  reason `certificate_expiring` (distinct from `certificate_expired`: the service
  still works, the response is to renew). Ready-made alerting rules are in
  `metrics.md` → *Alerting Examples*.
- ~~certificate SAN validation~~ **(implemented, reshaped)**: hostname matching
  against the SANs was always enforced; what was missing was visibility. The SAN
  *count* is now exported (`sentinel_tls_certificate_san_count`) and the names are
  kept in the diagnostics. The names are deliberately **not** a metric label — a
  CDN certificate carries hundreds, which would make one label value kilobytes
  long. The blackbox_exporter's `subjectalternative` label is the thing being
  declined here, on purpose.
- ~~weak cipher detection~~ **(partly implemented, partly reassigned)**: the
  *negotiated* suite and version are exported, and `tls.expect.min_version`
  enforces a floor. Detecting what a server *additionally* supports is not
  possible from a single handshake — Sentinel only ever offers TLS 1.2+ and Go's
  secure suites, so a weak suite is never agreed and a `forbid_weak_ciphers`
  switch would be a no-op. That enumeration needs several deliberately downgraded
  handshakes and is reassigned to the standalone `tls:` probe below.

- ~~standalone `tls:` probe~~ **(implemented)**: a fourth protocol block for
  endpoints that speak TLS immediately on connect — LDAPS 636, SMTPS 465,
  IMAPS 993, MQTT 8883, any bare TLS port. It reuses `internal/tlsdiag`
  unchanged and therefore emits the identical certificate/chain/OCSP series,
  plus three phase timings of its own (`sentinel_tls_dns_duration_seconds`,
  `_connect_duration_seconds`, `_handshake_duration_seconds`). Name resolution is
  performed explicitly so DNS and connect can be reported separately; addresses
  are tried in sequence, which — unlike blackbox's tcp module in the same
  benchmark — survives a host without an IPv6 route.
- ~~client certificates (mTLS), explicit SNI `server_name`~~ **(implemented)**:
  `tls.cert_file`/`tls.key_file`, `tls.server_name`, shared by `http.tls` and the
  new `tls:` block. The client certificate is treated as a credential and obeys
  the origin guard — a cross-origin redirect never receives it. Because TLS 1.3
  reports the client handshake complete before the server has validated that
  identity, the probe confirms afterwards that the connection was actually
  accepted; without that a rejected mTLS target would report success.
- ~~connection version cap~~ **(implemented)**: `tls.max_version` turns a target
  into a compatibility check ("does this server still serve TLS 1.2 clients?").
  A matching `min_version` was deliberately not added — `expect.min_version`
  enforces a floor *and* reports what was negotiated, and two options of the same
  name with different semantics is a configuration trap.
- ~~ALPN reporting~~ **(implemented for the `tls:` probe)**:
  `sentinel_tls_alpn_info{protocol}` from a configurable `alpn` list. It stays
  absent for HTTPS targets, whose transport negotiates no ALPN — reporting it
  there needs HTTP/2 support in the probe transport first.

Planned:

- ~~supported-version and supported-cipher enumeration~~ **(implemented)**:
  `tls.enumerate` tries TLS 1.0–1.3 and each of the 27 TLS 1.0–1.2 suites
  crypto/tls can offer in separate handshakes, after the measurement and at
  most once per interval (default 1h); `forbid_versions` and
  `forbid_insecure_ciphers` turn a hit into `tls_policy_violation`. A timeout
  is "unknown", never "refused". Not covered, because crypto/tls cannot speak
  them: SSLv3, export, NULL, anonymous and DHE suites — a hand-built
  ClientHello was considered and declined as security-sensitive custom code.
- ~~STARTTLS~~ **(implemented)**: `tls.starttls` upgrades SMTP, IMAP, POP3
  and LDAP connections before the handshake, with its own failure reason
  `starttls_failed`, phase `starttls` and
  `sentinel_tls_starttls_duration_seconds`. It was pulled forward from the mail
  protocols because the certificate behind port 587/143/389 is the question
  most often asked; checking the protocols themselves (authentication, mailbox
  access) stays with them in 0.3. Plaintext bytes received after the server's
  agreement are rejected rather than handed to the TLS layer.
- active OCSP / CRL revocation checking as a per-target opt-in

---

### DNS Improvements

- ~~DNSSEC validation~~ **(implemented, via the resolver)**: `dns.dnssec`
  sets the DO bit and requires the resolver's AD flag, otherwise the new
  failure reason `dnssec_unvalidated`; a bogus signature shows as `dns_error`
  (SERVFAIL). `sentinel_dns_rrsig_expiry_timestamp_seconds` reports the
  earliest signature expiry, so a stalled signer is visible days ahead.
  Sentinel trusts the resolver's verdict; validating the chain itself was
  considered and declined as security-sensitive custom code.
- ~~resolver comparison, multiple resolvers~~ **(implemented)**: `dns.servers`
  queries up to ten resolvers in parallel; every one must answer NOERROR and all
  must return the same answer set, otherwise the new failure reason
  `dns_mismatch`. Per-resolver series carry a `resolver` label and exist only
  for such targets, so single-resolver targets are unchanged. Failover
  semantics ("succeed if any answers") were deliberately not added: they hide
  exactly the broken resolver this is meant to find.
- ~~authoritative server checks~~ **(implemented)**: `dns.authoritative`
  finds a zone's nameservers through the configured resolver and asks every
  address directly, without recursion, for the SOA. A server answering without
  authority or with REFUSED fails with the new reason `dns_lame_delegation`,
  differing serials with `dns_mismatch`. Per-nameserver series include the
  serial. Only IPv4 addresses by default (`nameserver_family: both` adds IPv6),
  so a host without an IPv6 route does not fail permanently.

---

### Security, Tooling & CI

Implemented:

- static analysis wired into the build: `golangci-lint` (incl. **gosec**),
  reachable via `make lint`; **govulncheck** call-graph vulnerability scan via
  `make vuln`; combined `make sec` and a `make ci` that mirrors the pipeline.
- Forgejo Actions pipelines in `.forgejo/workflows/`: **CI** (gofmt, vet,
  golangci-lint, govulncheck, `go test -race`, build) on push/PR, and **Release**
  (cross-compiled `linux/darwin × amd64/arm64` static binaries + `SHA256SUMS`) on
  a `v*` tag. See `README.md` → *Continuous Integration*.

Known govulncheck output: adding `golang.org/x/crypto` (for `ocsp`, the only
non-stdlib dependency of the TLS work) surfaces the module-level advisory
**GO-2026-5932** — the unmaintained `x/crypto/openpgp` package. Sentinel does not
import it, the symbol-level scan reports zero vulnerabilities, and the advisory
has no fixed version because the package is unmaintained by design. `make vuln`
therefore still passes; the line in its output is expected, not a regression.

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

## Deferred / Optional

Explicitly pushed back and marked **optional**: not tied to any version and not
required for Sentinel to be fully useful. Revisit only when a concrete need
appears. (Distinct from *Declined* below, which were dropped on purpose, and
*Out of Scope*, which are hard non-goals.)

- **configuration templates** — reduce config duplication. Deferred: the flat
  `defaults` + `targets` model is adequate at the current scale, so the added
  complexity is not justified yet.
- **hot reload** (SIGHUP / config file watch) — apply config changes without a
  restart. Deferred: a rolling restart is acceptable for the current deployment
  model; low marginal value today.
- **HTTP/3 support** — probe over HTTP/3 / QUIC. Deferred: value is questionable
  right now — most monitored endpoints do not require QUIC-level probing and the
  standard-library HTTP/3 story is still maturing. Revisit if real demand shows.
- **diagnostics API** (`GET /api/v1/probes/{target}`: latest result, phases,
  error detail, redirect chain, TLS information). Deferred: the metrics, the
  structured log (including `phase` on timeouts) and the Grafana dashboard answer
  the diagnostic questions today; an API only pays off once something needs the
  data programmatically.
- **sharding** — stateless hash-based sharding via `--shard-index` /
  `--shard-count` flags. Every instance loads the *same* config but keeps only the targets whose name
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
  until probe CPU/RAM on one machine is the actual limit. Deferred: one
  instance covers the current target counts.

---

## Declined

Triaged on 2026-11-10 and dropped on purpose — not deferred. Each would add code
or operational surface without a problem Sentinel needs to solve. Reopen only
with a concrete case that the reasons below do not cover.

- **in-probe retry** (with retry metrics) — a retry inside the probe hides the
  very failure the probe exists to report and distorts the latency it measures.
  Transient failures are damped where alert tolerance already lives: `for:` in
  the Prometheus alerting rules.
- **signed release artifacts, SBOM generation on release** — the published
  `SHA256SUMS` are sufficient for the current distribution model;
  signing/attestation and an SBOM add pipeline complexity without a consumer
  that would verify them.
- **container image + image scanning** — deployment (container, systemd,
  Ansible) is handled outside this repository; the release binaries with
  `SHA256SUMS` are the hand-off.
- **configuration API, dynamic target management, Git-based configuration,
  configuration versioning** — the YAML file is the interface. Versioning and
  Git workflows belong to whatever deploys that file; `--validate` is the hook
  for a CI check.
- **web user interface** — target overview, status, latency graphs and
  certificate overview are covered by the generated Grafana dashboard on top of
  `/metrics`.
- **baseline analysis / anomaly detection** — comparing against history needs
  history, which Sentinel deliberately does not keep (see *Why Not Store History
  Internally?*). Prometheus recording rules and alerts over the existing
  histograms do this without a second source of truth.

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
