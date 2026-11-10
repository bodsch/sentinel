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
> custom headers, Basic/Bearer auth, per-target `max_body_bytes`), **DNS** (A/AAAA/MX/TXT/CNAME/SRV), and
> **TCP** (connect + `banner_regex`). Response validators are status / body_regex / headers /
> **JSONPath** (`expect.json`). Sections marked **(0.2+ / planned)** below — templates,
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
    block_private_redirects: false
```

All targets inherit these settings.

> **Note:** there is no `retries` field (see Retry); it is rejected as an
> unknown field. There is no `validate_tls` field either: TLS is
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

A target represents one monitored endpoint. It carries **exactly one** protocol
block — `http`, `dns`, `tcp` or `tls` — and configuring two (or none) is a
validation error.

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

### Blocking redirects to internal addresses

A monitored target decides where its redirects point. Without a guard, a
compromised or hostile target can answer with `Location: http://10.0.0.5/` and
make Sentinel probe an internal host it was never configured for — no
credentials or request body leak (the origin guard strips them), but status and
timing of the internal host become visible on `/metrics`. Set
`block_private_redirects` to refuse such hops:

```
targets:
  - name: partner-api
    http:
      url: https://api.partner.example/health
      block_private_redirects: true
```

- A redirect to a **different host** whose address is loopback, private
  (RFC 1918, `fc00::/7`), link-local (incl. `169.254.169.254`), unspecified,
  carrier-grade NAT (`100.64.0.0/10`) or `0.0.0.0/8` is not followed; the probe
  fails with `failure_reason="redirect_blocked"`.
- Redirects within the **target's own host** are always followed, whatever its
  address — `http://intranet` → `https://intranet:8443` keeps working, so the
  option is safe on internal targets too.
- The check runs on the address the connection is actually made to, after name
  resolution, so a public-looking name that resolves to `127.0.0.1` (DNS
  rebinding) is caught as well.
- **With `HTTP_PROXY`/`HTTPS_PROXY`** Sentinel only connects to the proxy, so the
  hop's name is resolved and checked beforehand instead. That is best effort:
  the proxy resolves the name again and may get a different answer, and a name
  Sentinel cannot resolve is left to the proxy.
- Opt-in, default `false`; can be set in `defaults.http` and switched off again
  per target. `follow_redirects: false` remains the strictest option.

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
- **Secrets** can be given inline (as above) or read from a file, so the
  credential need not live in the configuration:

  ```
  basic_auth:
    username: monitor
    password_file: /run/secrets/api-password
  ```

  ```
  bearer_token_file: /run/secrets/api-token
  ```

  `password_file` is mutually exclusive with `password`, `bearer_token_file`
  with `bearer_token`. The file is read **once at startup**; surrounding
  whitespace (e.g. a trailing newline) is trimmed. A missing, unreadable, empty
  or oversized (> 64 KiB) file stops the start with an error naming the target
  — the content is never logged. `--validate` does **not** open the files, so a
  CI dry-run works without access to the secrets. A rotated secret takes effect
  after a restart. Keep the files readable only by the Sentinel user (`0600`).

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

### Client certificates, SNI and version cap

These three settings live in the same `tls:` block and work identically under
`http.tls` and in a standalone `tls:` target.

```
targets:
  - name: internal-api
    http:
      url: https://192.0.2.10/health
      tls:
        ca_file: /etc/sentinel/internal-ca.pem
        cert_file: /etc/sentinel/sentinel-client.pem   # mutual TLS
        key_file:  /etc/sentinel/sentinel-client.key
        server_name: api.internal                      # SNI + name to validate
        max_version: "1.2"                             # compatibility check
```

- **`cert_file` / `key_file`** present a client certificate when the server asks
  for one. Both must be set together. The pair is read at startup, so a missing
  or malformed file stops the process instead of failing mysteriously later.
  Several targets sharing the same identity read it once.

  **The certificate is treated as a credential.** Like custom headers and
  `Authorization`, it is sent only to the target's own origin — a redirect to a
  different host, port or scheme never receives it. Handing an identity to a
  third party is precisely the leak the origin guard exists to prevent.

- **`server_name`** sets the SNI name *and* the name the certificate must be
  valid for. It is what makes the example above work at all: against an IP
  address Go sends no SNI, so the server would answer with its default
  certificate for a different name. This is curl's `--resolve` semantics.

  It does not weaken verification — a name the certificate does not carry still
  fails. With `follow_redirects` a cross-origin hop is validated against its own
  real hostname, so the override cannot be used to make a foreign certificate
  pass.

- **`max_version`** (`"1.2"` or `"1.3"`) caps the highest version Sentinel
  offers. Its purpose is the compatibility question: a target pinned to `"1.2"`
  fails exactly when the server no longer serves TLS 1.2 clients. Point two
  targets at the same endpoint with different caps to see the whole picture.

  There is deliberately **no** matching `min_version` here —
  `expect.min_version` already enforces a floor, and does so while still
  reporting which version the server actually negotiated. Configuring a floor
  above `max_version` is rejected: it could never be satisfied.

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
      type: A                  # A, AAAA, MX, TXT, CNAME or SRV (default A, case-insensitive)
      expected:                # optional; at least one answer must match
        - 93.184.216.34
```

Supported record types: **A, AAAA, MX, TXT, CNAME, SRV**. (DNSSEC validation
remains future work.)

CNAME and SRV examples:

```
targets:
  - name: www-alias
    dns:
      server: 1.1.1.1
      query: www.example.org
      type: CNAME
      expected: [edge.cdn.example.net]

  - name: sip-srv
    dns:
      server: 1.1.1.1
      query: _sip._tcp.example.org
      type: SRV
      expected:
        - "10 5 5060 sip.example.org"   # priority weight port target
```

An SRV answer is reported — and an SRV expectation written — in zone-file order
`priority weight port target`. A malformed SRV expectation is rejected at
config load, since it could never match.

Behaviour:

- The query uses UDP with EDNS0 (4096-byte buffer) and automatically retries over
  TCP if the response is truncated, so large answer sets are handled correctly.
- Success requires an RCODE of NOERROR. A non-NOERROR code (e.g. NXDOMAIN) fails
  with reason `dns_error`; the code is exposed as `sentinel_dns_response_code`.
- Without `expected`, a NOERROR response is a success even with zero answers —
  use `sentinel_dns_answer_count == 0` to alert on "did not resolve".
- With `expected`, at least one answer must match. Matching is type-aware: IPs
  compare numerically (A/AAAA), MX and CNAME hostnames compare
  case-insensitively, SRV compares all four fields (numbers numerically, the
  target case-insensitively, whitespace between fields is free), TXT compares
  exactly.
- A query of type A/AAAA that is answered through a CNAME chain reports only
  the address records; query type CNAME to watch the alias itself.

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

## TLS Configuration

A `tls:` target checks any endpoint that speaks TLS — **immediately on connect**
(LDAPS 636, SMTPS 465, IMAPS 993, POP3S 995, MQTT over TLS 8883, or any bare TLS
port) or **after a STARTTLS upgrade** (SMTP 587/25, IMAP 143, POP3 110, LDAP
389, see below). Such endpoints carry no HTTP to probe them with, while a `tcp:`
target only sees that a connection opens and never the certificate behind it.

```
targets:
  - name: ldaps
    tls:
      host: ldap.example.org
      port: 636
      expect:
        min_days_remaining: 21
```

The probe resolves the name, connects, completes the handshake, inspects the
certificate, and closes. No application protocol is spoken afterwards, apart
from the polite goodbye of a STARTTLS session.

| Key | Meaning |
|---|---|
| `host` | hostname or IP address (required) |
| `port` | TCP port, 1-65535 (required) |
| `alpn` | application protocols to offer, most preferred first |
| `starttls` | upgrade a plaintext connection first: `smtp`, `imap`, `pop3` or `ldap` (case-insensitive). Unset: TLS on connect |
| everything from *TLS verification* / *TLS expectations* | `ca_file`, `insecure_skip_verify`, `cert_file`/`key_file`, `server_name`, `max_version`, `expect` — written exactly as under `http.tls` |

**Metrics.** A `tls:` target emits the complete `sentinel_tls_certificate_*`,
`_chain_*`, `_version_info`, `_cipher_info`, `_alpn_info` and `_ocsp_*` set —
the same series an HTTPS target produces, because both feed the same
protocol-independent collector. In addition it gets three phase timings of its
own: `sentinel_tls_dns_duration_seconds`, `_connect_duration_seconds` and
`_handshake_duration_seconds`.

**ALPN.** Offering protocols makes the negotiated one visible as
`sentinel_tls_alpn_info{protocol="h2"}` — useful to check whether a load
balancer really announces HTTP/2:

```
targets:
  - name: lb-h2
    tls:
      host: lb.example.org
      port: 443
      alpn: ["h2", "http/1.1"]
```

**Name resolution.** Unlike a plain `net.Dial`, the probe resolves the name
itself and then tries the returned addresses in order. That is what allows DNS
and connect time to be reported separately — "slow to resolve" and "slow to
connect" call for entirely different investigations. It also means there is no
Happy Eyeballs (no parallel IPv4/IPv6 race): addresses are tried in sequence,
which keeps each measurement attributable to one address and still survives a
broken IPv6 path.

### STARTTLS

Ports that begin in plaintext and upgrade on command are covered by
`starttls`. The probe speaks just enough of the protocol to get there, then
runs the normal handshake and certificate inspection:

| `starttls` | Dialogue | Typical port |
|---|---|---|
| `smtp` | greeting `220` → `EHLO localhost` → `STARTTLS` must be offered → `STARTTLS` → `220` | 587, 25 |
| `imap` | greeting `* OK` → `a001 STARTTLS` → `a001 OK` | 143 |
| `pop3` | greeting `+OK` → `STLS` → `+OK` | 110 |
| `ldap` | StartTLS extended operation (OID `1.3.6.1.4.1.1466.20037`) → resultCode `success` | 389 |

```
targets:
  - name: submission
    tls:
      host: mail.example.org
      port: 587
      starttls: smtp
      expect:
        min_days_remaining: 21
```

- **`starttls_failed`** — the server answered but did not agree to upgrade: a
  refusing greeting (`554`, `* PREAUTH`, `-ERR`), STARTTLS missing from the
  SMTP `EHLO` reply, a negative answer, or a malformed or oversized reply. A
  network failure during the dialogue keeps its usual reason, and a timeout
  there logs `phase="starttls"`.
- **`sentinel_tls_starttls_duration_seconds`** — the plaintext dialogue,
  reported separately from the handshake. A slow greeting usually means a busy
  mail server, not a slow TLS stack.
- **Plaintext injection.** Bytes the server sends after agreeing but before the
  handshake are rejected (`starttls_failed`) instead of being handed to the TLS
  layer, so data injected on the plaintext leg cannot pass as protected.
- **No authentication.** The probe never logs in; it checks that the upgrade
  works and inspects the certificate. After the handshake it sends `QUIT`,
  `LOGOUT` or an LDAP unbind, so the server logs an orderly end of session.

### Not covered: cipher and version enumeration

What a server *additionally* supports cannot be learned from one handshake.
`max_version` gives a usable substitute for the common question: pin a second
target to `"1.2"` and its success tells you whether a TLS 1.2 client still gets
through. A full matrix would need several deliberately downgraded handshakes,
which a probe that also measures latency must not do.

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

## Retry

Not planned. A probe run is a single attempt: a retry inside the probe would hide the very failure
the probe exists to report and distort the latency it measures. Damp transient failures in the
Prometheus alerting rules instead, where alert tolerance already lives:

```yaml
- alert: SentinelProbeFailing
  expr: sentinel_probe_success == 0
  for: 2m
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
