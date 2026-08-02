# Benchmark harness — Sentinel vs blackbox_exporter

Reproducible harness that compares Sentinel against the Prometheus
`blackbox_exporter` for HTTP probing. Results and methodology live in
[`../docs/benchmark-vs-blackbox.md`](../docs/benchmark-vs-blackbox.md).

## What it measures

- **Dimension A — per-probe engine cost.** One HTTP probe against a local
  loopback target, apples-to-apples: Sentinel's in-process `BenchmarkProbe`
  (ns/op, allocs) vs blackbox's self-reported `probe_duration_seconds` and full
  `/probe` round-trip.
- **Dimension B — steady-state scale.** For growing target counts N, the RSS,
  CPU%, and scrape/probe latency of each process. At N targets and interval I,
  both systems perform `N/I` probes per second in aggregate; a load driver
  emulates Prometheus scraping N blackbox targets every I seconds.

Both processes run natively and are sampled with `ps`, so RSS/CPU are directly
comparable. CPU% is derived from cumulative CPU time and is quantised (~1
CPU-second granularity) — directional, not exact.

## Layout

| File | Purpose |
|---|---|
| `run.sh` | Self-provisioning orchestrator (build + download + measure). |
| `main.go` | `benchtool`: target server, config generator, blackbox probe sampler, load driver, scrape timer. Separate Go module, stdlib only. |
| `blackbox.yml` | blackbox `http_2xx` module matching Sentinel's defaults (GET, status 200, follow redirects, IPv4). |
| `.cache/` | Downloaded blackbox binary + built benchtool (git-ignored). |
| `run/`, `logs/`, `results.txt` | Per-run artefacts (git-ignored). |

## Running

```bash
# from the repo root; GOPATH must point at your module cache (see CLAUDE.md)
make benchmark

# or directly, with overrides
NS="100 1000 5000" INTERVAL_S=5 bench/run.sh
```

First run downloads a pinned `blackbox_exporter` release into `.cache/`;
subsequent runs reuse it. Output is written to `bench/results.txt` and echoed.

### Environment overrides

| Var | Default | Meaning |
|---|---|---|
| `BB_VERSION` | `0.28.0` | blackbox_exporter release to benchmark against |
| `NS` | `100 500 1000 2000` | target counts for dimension B |
| `INTERVAL_S` | `5` | probe interval (seconds) |
| `WARMUP_S` | `12` | warmup before sampling |
| `WINDOW_S` | `15` | sampling window |

## Notes and limitations

- Supported hosts: linux and darwin, amd64 and arm64.
- The loopback target removes network RTT to isolate the probe engine; real
  deployments narrow the absolute gap.
- `process_resident_memory_bytes` is Linux-only in blackbox's own metrics; this
  harness sidesteps that by sampling RSS externally with `ps` on both hosts.
- `benchtool` is a separate module (`bodsch.me/sentinel/bench`) so it never
  pulls dependencies into the main sentinel module; it is not covered by the
  root `go test ./...` / `go vet ./...`.
