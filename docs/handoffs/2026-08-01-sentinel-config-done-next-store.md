# Handover — Sentinel: 0.1 scaffold + `internal/config` done, next is `internal/store`

Date: 2026-08-01 · Repo: `/Users/bodo.schulz/src/private/go/sentinel` · Branch: `main` (nothing committed yet)

## What Sentinel is
HTTP-first synthetic monitoring engine for Prometheus. Version 0.1 is a deliberately narrow
vertical slice: **HTTP/HTTPS only**, full runtime skeleton. Product/design context and the full
0.1 scope live in the design docs — do **not** re-derive them:
- Design decisions + running status: `brainstorms/2026-08-01-sentinel-design.md` (authoritative; 28 Q&A, condensed 0.1 scope, deferred-to-0.2 list, review outcome).
- Specs: `README.md`, `architecture.md`, `configuration.md`, `metrics.md`, `Roadmap.md` (already reconciled to the 0.1 decisions).
- Repo conventions / hard requirements: `CLAUDE.md` (module `bodsch.me/sentinel`, English comments, slog, `/metrics`, versioned binary, Linux+macOS, small deps).

## Current state (all builds; `gofmt` clean, `go vet` clean, `go test -race ./...` green)
Implemented packages:
- `pkg/version` — ldflags-stamped build info.
- `internal/probe` — `Prober` interface, typed `Result`/`Timings`/`Diagnostics`, `FailureReason` enum + `Valid()`.
- `internal/clock` — `Clock` interface + `Real` + deterministic race-safe `Fake` (for scheduler tests).
- `internal/logging` — slog setup, JSON default, fixed field schema, `WithProbe`.
- `internal/config` — YAML load (`gopkg.in/yaml.v3`, `KnownFields(true)`), defaults→targets merge, full validation, `--validate` wired in `cmd/sentinel/main.go`. Adversarially reviewed and hardened (7 findings fixed; see brainstorm file for the table). Tests in `config_test.go`, `fixes_test.go`, `example_test.go`.
- `cmd/sentinel/main.go` — flags (`--config/--validate/--version/--log-level/--log-format/--listen`), fail-fast load. The probe **runtime is intentionally not wired yet** — a normal start prints "probe runtime is not implemented yet" and exits non-zero (honest stub, no faking).
- `config.example.yaml` — valid 0.1 example, guarded by `example_test.go`.
- `Makefile` — `make ci/build/test/release`, `CGO_ENABLED=0`, cross-build linux+darwin ×amd64/arm64.

Dependency: `gopkg.in/yaml.v3` (direct). Go 1.26.

## Build / verify
```bash
export GOPATH="$HOME/src/go"; export GOMODCACHE=$GOPATH/pkg/mod
cd /Users/bodo.schulz/src/private/go/sentinel
go test -race ./...          # or: make ci  (needs golangci-lint installed)
make build && ./bin/sentinel --validate --config config.example.yaml
```

## Next task (requested): `internal/store`
Thread-safe result store — the shared seam between the scheduler (writes probe `Result`s) and the
metrics collector (reads current state live at scrape time). Key decisions already made:
- `name` is the hard primary key (uniqueness already enforced in config validation).
- Concurrent write (workers) + read (collector on scrape) → `sync.RWMutex` or equivalent; must pass `-race`.
- Removed targets: **removed immediately**, no tombstone (relevant later for reload; 0.1 has no reload).
- Store holds only current state (success, failure reason, timings, timestamp, protocol diagnostics) — no history (that is Prometheus's job).
- Reuse the typed `probe.Result` from `internal/probe`; do not invent a parallel struct.

After the store, the natural order is: `internal/probe/http` (httptrace phase timings, fresh
connection per run, redirects incl. loop + HTTPS→HTTP downgrade, manual TLS inspection) →
`internal/scheduler` (ticker-per-target + semaphore + skip-if-running, uses `internal/clock`) →
`internal/metrics` (self-registering collectors, `probe_success` + vanishing `probe_failure_info`,
fixed label set, `build_info`) → `internal/server` (`/metrics`, `/healthz`, `/readyz` on `:8080`) →
wire it all in `main` with graceful shutdown (drain, default 10s, in-flight discarded).

## Conventions to keep
- No committing/pushing until the user asks; if committing, branch first (currently on `main`).
- Complete, compiling, tested files only — no half-wired pseudocode. Each package builds and has `-race` tests.
- English comments/docstrings; deliver full files, not diffs.
- Respond to the user in German.
- Interval-governance (a minimum interval floor) was **explicitly declined** for this milestone — do not add it without asking.

## Suggested skills
- `verify` — after implementing the store (and each subsequent runtime package), exercise it end-to-end, not just unit tests.
- `code-review` (or a general-purpose review subagent, as done for `internal/config`) — run an adversarial pass on each new package before considering it done.
- `grill-me` — if a new design ambiguity surfaces that the brainstorm file does not already resolve.

## Open threads / flags
- Nothing is committed. Working tree: new files under `cmd/ internal/ pkg/ brainstorms/ docs/ .claude/` plus `Makefile`, `CLAUDE.md`, `config.example.yaml`, `go.mod`, `go.sum`; `configuration.md` modified.
- Doc nacharbeit from the grill session is fully done (README/architecture/metrics/configuration/Roadmap/CLAUDE.md reconciled).
- No blocking design questions remain for 0.1.
