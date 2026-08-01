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

  retries: 2

  http:

    follow_redirects: true

    max_redirects: 10

    validate_tls: true
```

All targets inherit these settings.

---

## Templates

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

  team: platform

  environment: production

  location: datacenter-1
```
These values become Prometheus labels.

---

## HTTP Configuration

Example:

```
http:

  url: https://example.org

  method: GET

  timeout: 10s

  follow_redirects: true

  max_redirects: 10
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

## JSON Validation

Example:

```
http:

  url: https://api.example.org/status


  expect:

    json:

      "$.status": "healthy"
```

---

## XPath Validation

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

## Retry Configuration

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

Timeouts exist on multiple levels.

Example:

```
timeout:

  total: 10s

  dns: 2s

  connect: 3s

  tls: 5s
```
---

## Proxy Support

Optional HTTP proxy configuration.

Example:
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

## Hot Reload

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

```
defaults:

  interval: 30s

  timeout: 10s


templates:

  website:

    http:

      expect:

        status: 200



targets:


  - name: homepage

    template: website


    tags:

      service: frontend


    http:

      url: https://example.org



  - name: smtp

    tcp:

      address: mail.example.org:25

      expect:

        banner: "ESMTP"
```

---

## Design Goals

The Sentinel configuration format intentionally favors:

- clarity over compactness
- explicit behavior
- safe defaults
- automation friendliness

The configuration should be understandable without reading implementation details.
