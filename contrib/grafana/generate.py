#!/usr/bin/env python3
"""Generate the Grafana dashboard in this directory.

    python3 contrib/grafana/generate.py [output-dir]

The JSON file is output: change this script and run `make dashboards` instead
of editing it, or the next run undoes the edit.

Every metric used here was taken from the collector definitions in internal/
(not only from metrics.md) and checked for a production call site, so no panel
reads a series that no binary exports. Standard library only.
"""

import json
import os
import sys

DS = {"type": "prometheus", "uid": "${datasource}"}
NS = "sentinel"
out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))

# Selector for Sentinel's own series (build info, scrape cost, runtime).
SEL = '{instance=~"$instance"}'
# Label matchers for probe series; P is the braced form.
F = ('instance=~"$instance",environment=~"$environment",service=~"$service",'
     'type=~"$type",target=~"$target"')
P = "{" + F + "}"


class B:
    """Lays panels out left to right on a 24-column grid, wrapping lines."""

    def __init__(self):
        self.panels, self.y, self.id = [], 0, 1
        self.x, self.rowh = 0, 0

    def row(self, title):
        self._nl()
        self.panels.append({"type": "row", "title": title, "id": self._nid(), "collapsed": False,
                            "gridPos": {"h": 1, "w": 24, "x": 0, "y": self.y}, "panels": []})
        self.y += 1

    def _nid(self):
        self.id += 1
        return self.id

    def _nl(self):
        if self.x:
            self.y += self.rowh
            self.x, self.rowh = 0, 0

    def add(self, p, w, h):
        if self.x + w > 24:
            self._nl()
        p["id"] = self._nid()
        p["datasource"] = DS
        p["gridPos"] = {"h": h, "w": w, "x": self.x, "y": self.y}
        self.panels.append(p)
        self.x += w
        self.rowh = max(self.rowh, h)


def t(expr, legend="", instant=False, fmt=None, ref="A"):
    d = {"datasource": DS, "expr": expr, "legendFormat": legend or "__auto", "refId": ref}
    if instant:
        d.update(instant=True, range=False)
    if fmt:
        d["format"] = fmt
    return d


def thresholds(steps):
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for v, c in steps]}


def stat(title, targets, unit="none", steps=None, desc="", mappings=None, text_mode="value", decimals=None):
    d = {"unit": unit, "thresholds": thresholds(steps or [(None, "green")]), "color": {"mode": "thresholds"}}
    if mappings:
        d["mappings"] = mappings
    if decimals is not None:
        d["decimals"] = decimals
    return {"type": "stat", "title": title, "description": desc, "targets": targets,
            "fieldConfig": {"defaults": d, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                        "colorMode": "background", "graphMode": "none", "textMode": text_mode,
                        "justifyMode": "center"}}


def ts(title, targets, unit="short", stack=False, bars=False, desc="", steps=None, min0=True,
       overrides=None, maxv=None):
    custom = {"drawStyle": "bars" if bars else "line", "lineWidth": 1, "fillOpacity": 60 if bars else 10,
              "showPoints": "never", "spanNulls": False,
              "stacking": {"mode": "normal" if stack else "none", "group": "A"}}
    d = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}
    if min0:
        d["min"] = 0
    if maxv is not None:
        d["max"] = maxv
    if steps:
        d["thresholds"] = thresholds(steps)
        custom["thresholdsStyle"] = {"mode": "line+area"}
    return {"type": "timeseries", "title": title, "description": desc, "targets": targets,
            "fieldConfig": {"defaults": d, "overrides": overrides or []},
            "options": {"legend": {"displayMode": "table", "placement": "bottom", "calcs": ["lastNotNull", "max"]},
                        "tooltip": {"mode": "multi", "sort": "desc"}}}


def timeline(title, targets, mappings, desc=""):
    return {"type": "state-timeline", "title": title, "description": desc, "targets": targets,
            "fieldConfig": {"defaults": {"mappings": mappings, "color": {"mode": "thresholds"},
                                         "thresholds": thresholds([(None, "red"), (1, "green")]),
                                         "custom": {"fillOpacity": 80, "lineWidth": 0}},
                            "overrides": []},
            "options": {"showValue": "never", "mergeValues": True, "rowHeight": 0.8, "alignValue": "left",
                        "legend": {"showLegend": False}, "tooltip": {"mode": "single"}}}


def table(title, targets, desc="", exclude=(), rename=None, order=None, overrides=None, sort=None,
          merge=True):
    excl = {"Time": True, "job": True, "instance": True, "__name__": True}
    excl.update({k: True for k in exclude})
    tr = [{"id": "merge", "options": {}}] if merge else []
    tr.append({"id": "organize", "options": {"excludeByName": excl, "indexByName": order or {},
                                             "renameByName": rename or {}}})
    if sort:
        tr.append({"id": "sortBy", "options": {"sort": [{"field": sort[0], "desc": sort[1]}]}})
    return {"type": "table", "title": title, "description": desc, "targets": targets,
            "transformations": tr,
            "fieldConfig": {"defaults": {"custom": {"align": "auto"}}, "overrides": overrides or []},
            "options": {"showHeader": True, "cellHeight": "sm"}}


def col(name, unit=None, steps=None, decimals=None, mappings=None):
    """Field override for one table column: unit, coloured background, mappings."""
    props = []
    if unit:
        props.append({"id": "unit", "value": unit})
    if decimals is not None:
        props.append({"id": "decimals", "value": decimals})
    if mappings:
        props.append({"id": "mappings", "value": mappings})
    if steps:
        props.append({"id": "thresholds", "value": thresholds(steps)})
        props.append({"id": "custom.cellOptions", "value": {"type": "color-background"}})
    return {"matcher": {"id": "byName", "options": name}, "properties": props}


def color_override(name, color):
    return {"matcher": {"id": "byName", "options": name},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}]}


def flag_map(one, zero):
    """Value mapping for a 1/0 gauge, coloured green for the good value."""
    good, bad = ("green", "red")
    return [{"type": "value", "options": {"1": {"text": one[0], "color": good if one[1] else bad},
                                          "0": {"text": zero[0], "color": good if zero[1] else bad}}}]


def own(expr):
    """Restricts an unprefixed metric to Sentinel's own scrape targets.

    process_*, go_*, up and scrape_* carry no service prefix: every Go exporter
    and Prometheus itself export them. A filter on instance alone matches all
    of them once the variable is "All" (allValue .*), and the CPU panel then
    shows whatever else runs there. Joining on sentinel_build_info by job and
    instance keeps exactly the targets that are Sentinel.
    """
    return f'({expr}) and on (job, instance) {NS}_build_info{SEL}'


def var(name, label, query, hide=0):
    return {"name": name, "label": label, "type": "query", "datasource": DS,
            "query": {"query": query, "refId": name}, "definition": query,
            "includeAll": True, "multi": True, "allValue": ".*", "current": {}, "refresh": 2,
            "sort": 1, "hide": hide}


def chained(label):
    """label_values query for a probe label, narrowed to the selected instances."""
    return f'label_values({NS}_probe_success{{instance=~"$instance"}}, {label})'


b = B()

# --- overview ----------------------------------------------------------------
SCRAPE_MAP = [{"type": "value", "options": {"0": {"text": "down", "color": "red"},
                                            "1": {"text": "up", "color": "green"}}},
              {"type": "special", "options": {"match": "null", "result": {"text": "no scrape", "color": "red"}}}]

b.row("Overview")
b.add(stat("Version", [t(f'{NS}_build_info{SEL}', "{{version}} ({{commit}})", instant=True)],
           text_mode="name", steps=[(None, "blue")], desc="After a rollout: does every instance run the same build?"), 3, 4)
b.add(stat("Scrape", [t(f'min(up and on (job, instance) last_over_time({NS}_build_info{SEL}[1d]))', instant=True)],
           mappings=SCRAPE_MAP, steps=[(None, "red"), (1, "green")],
           desc="Prometheus' own up for the Sentinel targets. Sentinel exports no readiness gauge; /readyz is a "
                "separate HTTP check. last_over_time keeps a dead instance in the join for a day, so it shows as "
                "down instead of disappearing."), 3, 4)
b.add(stat("Uptime", [t(f"time() - max({own('process_start_time_seconds')})", instant=True)], "s",
           steps=[(None, "blue")]), 3, 4)
b.add(stat("Targets", [t(f'count({NS}_probe_success{P}) or vector(0)', instant=True)],
           steps=[(None, "blue")], decimals=0, desc="Targets in the result store matching the filters."), 3, 4)
b.add(stat("Failing", [t(f'count({NS}_probe_success{P} == 0) or vector(0)', instant=True)],
           steps=[(None, "green"), (1, "red")], decimals=0,
           desc="The primary alert from metrics.md: sentinel_probe_success == 0. The reason is in the "
                "failure table below."), 3, 4)
b.add(stat("Earliest chain expiry", [t(f'min({NS}_tls_chain_earliest_remaining_days{P})', instant=True)], "d",
           steps=[(None, "red"), (14, "orange"), (30, "green")], decimals=0,
           desc="Across the whole chain, not the leaf: an intermediate or root expiring first breaks the "
                "connection just as surely. Red below 14 days matches the recommended alert."), 3, 4)
b.add(stat("Skipped runs (1h)", [t(f'sum(increase({NS}_probe_skipped_total{P}[1h])) or vector(0)', instant=True)],
           steps=[(None, "green"), (1, "orange")], decimals=0,
           desc="A run is skipped when the previous one of the same target is still in flight. Rising means the "
                "interval is too tight for how long the target takes."), 3, 4)
b.add(stat("Render cost", [t(f'max({NS}_scrape_duration_seconds{SEL})', instant=True)], "s",
           steps=[(None, "green"), (1, "orange"), (5, "red")], decimals=3,
           desc="Time to gather all series on the last scrape (one scrape behind). Size scrape_timeout 2-3x above "
                "it; orange/red assume the documented 10s timeout."), 3, 4)

# --- availability -------------------------------------------------------------
b.row("Availability")
b.add(timeline("Probe state", [t(f'max by (target) ({NS}_probe_success{P})', "{{target}}")],
               [{"type": "value", "options": {"0": {"text": "failing", "color": "red"},
                                              "1": {"text": "ok", "color": "green"}}}],
               desc="Sampled at scrape time: a failure shorter than the scrape interval can be missed."), 24, 9)
b.add(table("Targets",
            [t(f'{NS}_probe_success{P}', instant=True, fmt="table", ref="A"),
             t(f'avg_over_time({NS}_probe_success{P}[$__range])', instant=True, fmt="table", ref="B"),
             t(f'time() - {NS}_probe_last_success_timestamp_seconds{P}', instant=True, fmt="table", ref="C")],
            desc="Availability is the share of scrapes, not of probes, in the selected range. "
                 "An empty 'since last success' means the target never succeeded since Sentinel started.",
            rename={"Value #A": "state", "Value #B": "availability", "Value #C": "since last success"},
            order={"target": 0, "type": 1, "service": 2, "environment": 3, "location": 4},
            overrides=[col("state", mappings=flag_map(("ok", True), ("failing", False)),
                           steps=[(None, "red"), (1, "green")]),
                       col("availability", "percentunit", [(None, "red"), (0.99, "orange"), (0.999, "green")], 3),
                       col("since last success", "s")],
            sort=("availability", False)), 14, 10)
b.add(table("Current failures",
            [t(f'{NS}_probe_failure_info{P}', instant=True, fmt="table")],
            desc="sentinel_probe_failure_info exists only while a target fails, so this table is empty when "
                 "everything is fine. Exactly one reason per failing target.",
            exclude=("Value", "environment", "location"),
            order={"target": 0, "type": 1, "reason": 2}, merge=False), 10, 10)
b.add(ts("Failing targets by reason", [t(f'count by (reason) ({NS}_probe_failure_info{P})', "{{reason}}")],
         stack=True, bars=True,
         desc="certificate_expiring and tls_policy_violation only occur for targets with tls.expect."), 12, 8)
b.add(ts("Skipped runs", [t(f'sum by (target) (increase({NS}_probe_skipped_total{P}[$__rate_interval]))', "{{target}}")],
         bars=True, desc="Overload protection of the scheduler. Lengthen the target's interval or shorten its timeout."),
      12, 8)

# --- latency -------------------------------------------------------------------
b.row("Latency")
b.add(ts("Probe duration p95",
         [t(f'histogram_quantile(0.95, sum by (le, target) (rate({NS}_probe_duration_seconds_bucket{P}[$__rate_interval])))',
            "{{target}}")],
         "s", desc="All probe types, successful runs only (failures are carried by probe_success). For HTTP this "
                   "covers all redirect hops. Buckets end at 10s."), 12, 8)
b.add(ts("HTTP TTFB p95",
         [t(f'histogram_quantile(0.95, sum by (le, target) (rate({NS}_http_ttfb_seconds_bucket{P}[$__rate_interval])))',
            "{{target}}")],
         "s", steps=[(None, "transparent"), (1, "red")],
         desc="Time from request sent to first response byte, successful HTTP probes only. The red line is the "
              "'slow response' alert from metrics.md (p95 > 1s over 10m)."), 12, 8)
b.add(ts("Probe duration p50 / p95 / p99 (selection)",
         [t(f'histogram_quantile({q}, sum by (le) (rate({NS}_probe_duration_seconds_bucket{P}[$__rate_interval])))',
            f"p{int(q * 100)}", ref=r) for q, r in ((0.5, "A"), (0.95, "B"), (0.99, "C"))],
         "s", desc="One distribution over every selected target. Narrow the target filter to read a single one."), 12, 8)
b.add(ts("HTTP TTFB mean",
         [t(f'sum by (target) (rate({NS}_http_ttfb_seconds_sum{P}[$__rate_interval])) '
            f'/ sum by (target) (rate({NS}_http_ttfb_seconds_count{P}[$__rate_interval]))', "{{target}}")],
         "s", desc="Mean from the histogram's sum and count; finer than the bucket-based p95 for fast targets."), 12, 8)

# --- HTTP phases ---------------------------------------------------------------
b.row("HTTP phases (final hop, last probe)")
for title, metric, desc in (
        ("DNS", "http_dns_duration_seconds", "Zero when the connection was reused or the host is an IP address."),
        ("TCP connect", "http_tcp_connect_duration_seconds", ""),
        ("TLS handshake", "http_tls_handshake_duration_seconds", "Zero for plain HTTP."),
        ("Download", "http_download_duration_seconds", "Reading the response body.")):
    b.add(ts(title, [t(f'{NS}_{metric}{P}', "{{target}}")], "s",
             desc=(desc + " " if desc else "") + "Last-value gauge: shows the probe current at each scrape, "
                                                 "not every probe."), 6, 7)
b.add(ts("Status code", [t(f'{NS}_http_status_code{P}', "{{target}}")], min0=False,
         desc="Absent when no response arrived. The failure reason is http_status_error when it does not match."),
      8, 7)
b.add(ts("Redirects followed", [t(f'{NS}_http_redirects{P}', "{{target}}")], desc="On the last probe."), 8, 7)
b.add(ts("Served over TLS", [t(f'{NS}_http_ssl{P}', "{{target}}")], maxv=1,
         desc="1 -> 0 is a target that silently stopped using TLS (the 'TLS silently dropped' alert)."), 8, 7)

# --- DNS, TCP and TLS probes ----------------------------------------------------
b.row("DNS, TCP and TLS probes")
b.add(ts("DNS query duration", [t(f'{NS}_dns_query_duration_seconds{P}', "{{target}}")], "s"), 8, 7)
b.add(ts("DNS response code", [t(f'{NS}_dns_response_code{P}', "{{target}}")],
         steps=[(None, "transparent"), (1, "red")],
         desc="RCODE: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED."), 8, 7)
b.add(ts("DNS answer count", [t(f'{NS}_dns_answer_count{P}', "{{target}}")],
         desc="Records of the queried type. A drop to zero with NOERROR is an empty answer, not an outage."), 8, 7)
b.add(ts("TCP connect duration", [t(f'{NS}_tcp_connect_duration_seconds{P}', "{{target}}")], "s",
         desc="Includes name resolution."), 6, 7)
for title, metric in (("TLS probe: DNS", "tls_dns_duration_seconds"),
                      ("TLS probe: connect", "tls_connect_duration_seconds"),
                      ("TLS probe: handshake", "tls_handshake_duration_seconds")):
    b.add(ts(title, [t(f'{NS}_{metric}{P}', "{{target}}")], "s",
             desc="Only type=\"tls\" targets; HTTPS reports the same phases in the HTTP row."), 6, 7)

# --- certificates -----------------------------------------------------------------
b.row("TLS and certificates")
b.add(stat("Chain not verified", [t(f'count({NS}_tls_chain_verified{P} == 0) or vector(0)', instant=True)],
           steps=[(None, "green"), (1, "red")], decimals=0,
           desc="Also counts targets with tls.insecure_skip_verify: they probe successfully but are untrusted."), 4, 4)
b.add(stat("Certificate invalid", [t(f'count({NS}_tls_certificate_valid{P} == 0) or vector(0)', instant=True)],
           steps=[(None, "green"), (1, "red")], decimals=0,
           desc="Chain, hostname and validity window. Stays honest under insecure_skip_verify."), 4, 4)
b.add(stat("OCSP revoked", [t(f'count({NS}_tls_ocsp_info{{{F},status="revoked"}}) or vector(0)', instant=True)],
           steps=[(None, "green"), (1, "red")], decimals=0,
           desc="Does not fail the probe unless tls.expect.require_ocsp_stapling is set, hence its own tile."), 4, 4)
b.add(stat("OCSP staple stale", [t(f'count({NS}_tls_ocsp_next_update_timestamp_seconds{P} < time()) or vector(0)',
                                   instant=True)],
           steps=[(None, "green"), (1, "orange")], decimals=0,
           desc="Past NextUpdate: browsers may reject it while Sentinel's probe still succeeds."), 4, 4)
b.add(stat("SHA-1 signatures", [t(f'count({NS}_tls_certificate_info{{{F},signature_algorithm=~"SHA1.*"}}) or vector(0)',
                                  instant=True)],
           steps=[(None, "green"), (1, "red")], decimals=0, desc="A finding regardless of expiry."), 4, 4)
b.add(stat("Weak RSA keys", [t(f'count({NS}_tls_certificate_key_bits{P} < 2048 and on (job, instance, target) '
                               f'{NS}_tls_certificate_info{{{F},public_key_algorithm="RSA"}}) or vector(0)', instant=True)],
           steps=[(None, "green"), (1, "red")], decimals=0, desc="RSA keys below 2048 bits."), 4, 4)
b.add(table("Certificates",
            [t(f'{NS}_tls_chain_earliest_remaining_days{P}', instant=True, fmt="table", ref="A"),
             t(f'{NS}_tls_certificate_remaining_days{P}', instant=True, fmt="table", ref="B"),
             t(f'{NS}_tls_certificate_valid{P}', instant=True, fmt="table", ref="C"),
             t(f'{NS}_tls_chain_verified{P}', instant=True, fmt="table", ref="D"),
             t(f'{NS}_tls_chain_length{P}', instant=True, fmt="table", ref="E"),
             t(f'{NS}_tls_certificate_key_bits{P}', instant=True, fmt="table", ref="F"),
             t(f'{NS}_tls_ocsp_stapled{P}', instant=True, fmt="table", ref="G"),
             t(f'{NS}_tls_certificate_self_signed{P}', instant=True, fmt="table", ref="H"),
             t(f'{NS}_tls_certificate_san_count{P}', instant=True, fmt="table", ref="I")],
            desc="Only targets that negotiated TLS appear here: plain HTTP emits no sentinel_tls_* series at all.",
            exclude=("environment", "location"),
            rename={"Value #A": "chain days", "Value #B": "leaf days", "Value #C": "valid",
                    "Value #D": "chain verified", "Value #E": "chain length", "Value #F": "key bits",
                    "Value #G": "OCSP stapled", "Value #H": "self-signed", "Value #I": "SANs"},
            order={"target": 0, "type": 1, "service": 2},
            overrides=[col("chain days", "d", [(None, "red"), (14, "orange"), (30, "green")], 0),
                       col("leaf days", "d", [(None, "red"), (14, "orange"), (30, "green")], 0),
                       col("valid", mappings=flag_map(("yes", True), ("no", False)), steps=[(None, "red"), (1, "green")]),
                       col("chain verified", mappings=flag_map(("yes", True), ("no", False)),
                           steps=[(None, "red"), (1, "green")]),
                       col("OCSP stapled", mappings=flag_map(("yes", True), ("no", True))),
                       col("self-signed", mappings=flag_map(("yes", False), ("no", True)),
                           steps=[(None, "green"), (1, "red")])],
            sort=("chain days", False)), 24, 9)
b.add(ts("Remaining days (chain)", [t(f'{NS}_tls_chain_earliest_remaining_days{P}', "{{target}}")], "d",
         steps=[(None, "red"), (14, "orange"), (30, "transparent")],
         desc="A sawtooth: falls steadily and jumps back on renewal. A line that does not jump back is the finding."),
      12, 8)
b.add(table("Certificate identity", [t(f'{NS}_tls_certificate_info{P}', instant=True, fmt="table")],
            desc="Subject alternative names are deliberately not a label; see san_count. Serial and fingerprint "
                 "are lowercase hex as openssl and CT logs show them.",
            exclude=("Value", "environment", "location", "service", "type"),
            order={"target": 0, "subject_cn": 1, "issuer_cn": 2}, merge=False), 12, 8)
b.add(ts("Negotiated TLS versions", [t(f'count by (version) ({NS}_tls_version_info{P})', "{{version}}")],
         stack=True, desc="What was negotiated, not what the server additionally supports."), 8, 7)
b.add(ts("Negotiated cipher suites", [t(f'count by (cipher) ({NS}_tls_cipher_info{P})', "{{cipher}}")],
         stack=True), 8, 7)
b.add(ts("OCSP staple status", [t(f'count by (status) ({NS}_tls_ocsp_info{P})', "{{status}}")], stack=True,
         overrides=[color_override("good", "green"), color_override("revoked", "red"),
                    color_override("unknown", "orange"), color_override("invalid", "purple")],
         desc="invalid: the staple was present but not signed by the issuer or not for this certificate."), 8, 7)

# --- scrape cost and runtime --------------------------------------------------------
b.row("Scrape cost")
b.add(ts("Render vs. full scrape",
         [t(f'{NS}_scrape_duration_seconds{SEL}', "render {{instance}}"),
          t(own('scrape_duration_seconds'), "full scrape {{instance}}", ref="B")], "s",
         desc="Render is Sentinel's gather time; the full scrape adds encoding and network as measured by "
              "Prometheus. Raising scrape_interval lowers this cost without slowing down probing."), 12, 7)
b.add(ts("Samples per scrape", [t(own('scrape_samples_scraped'), "{{instance}}")],
         desc="O(N) in targets: about 10 series per plain HTTP target, 25 per HTTPS target, plus 14 per histogram (12 buckets, sum, count)."),
      12, 7)

b.row("Process and runtime")
b.add(ts("CPU", [t(own('rate(process_cpu_seconds_total[$__rate_interval])'), "{{instance}}")], "percentunit",
         desc="1 = one core."), 6, 7)
b.add(ts("Memory", [t(own('process_resident_memory_bytes'), "RSS {{instance}}"),
                    t(own('go_memstats_heap_inuse_bytes'), "heap {{instance}}", ref="B")], "bytes",
         desc="RSS is reported on Linux only; on macOS only the heap line appears."), 6, 7)
b.add(ts("Goroutines", [t(own('go_goroutines'), "{{instance}}")],
         desc="Roughly constant per target. Steady growth at a fixed target count is a leak."), 6, 7)
b.add(ts("Open file descriptors", [t(own('process_open_fds'), "open {{instance}}"),
                                   t(own('process_max_fds'), "limit {{instance}}", ref="B")]), 6, 7)

dashboard = {
    "uid": "sentinel", "title": "Sentinel",
    "description": "Synthetic monitoring: probe state and failure reasons, latency, HTTP phases, DNS/TCP/TLS "
                   "probes, certificates, scrape cost, runtime.",
    "tags": ["sentinel", "synthetic-monitoring"],
    "schemaVersion": 39, "version": 1, "editable": True, "graphTooltip": 1,
    "time": {"from": "now-24h", "to": "now"}, "refresh": "1m", "timezone": "browser",
    "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                              "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                              "name": "Annotations & Alerts", "type": "dashboard"}]},
    "templating": {"list": [
        {"name": "datasource", "label": "Data source", "type": "datasource", "query": "prometheus",
         "current": {}, "hide": 0, "refresh": 1},
        var("instance", "Instance", f"label_values({NS}_build_info, instance)"),
        var("environment", "Environment", chained("environment")),
        var("service", "Service", chained("service")),
        var("type", "Type", chained("type")),
        var("target", "Target", chained("target")),
    ]},
    "panels": b.panels,
}

with open(os.path.join(out_dir, "sentinel.json"), "w") as f:
    json.dump(dashboard, f, indent=2, ensure_ascii=False)
    f.write("\n")
