#!/usr/bin/env bash
#
# Sentinel vs blackbox_exporter benchmark harness.
#
# Self-provisioning and repo-relative: builds the sentinel binary and the
# benchtool helper, downloads a pinned blackbox_exporter release, then runs
# two measurement dimensions against a local loopback target:
#
#   Dimension A  per-probe engine cost (apples-to-apples)
#   Dimension B  steady-state scale: RSS/CPU/latency at growing target counts
#
# See docs/benchmark-vs-blackbox.md for methodology and interpretation.
#
# Usage:
#   bench/run.sh
#
# Overridable via environment:
#   BB_VERSION   blackbox_exporter release to benchmark against (default 0.28.0)
#   NS           space-separated target counts       (default "100 500 1000 2000")
#   INTERVAL_S   probe interval in seconds            (default 5)
#   WARMUP_S     warmup before sampling               (default 12)
#   WINDOW_S     sampling window                       (default 15)
#
# Supported hosts: linux and darwin, amd64 and arm64. RSS/CPU are sampled with
# `ps` for both processes so the numbers are directly comparable; CPU% is
# derived from cumulative CPU time and is quantised (~1 CPU-second granularity).
set -uo pipefail

BENCH="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$BENCH/.." && pwd)"
CACHE="$BENCH/.cache"
BB_VERSION="${BB_VERSION:-0.28.0}"
INTERVAL_S="${INTERVAL_S:-5}"
WARMUP_S="${WARMUP_S:-12}"
WINDOW_S="${WINDOW_S:-15}"
read -r -a NS <<<"${NS:-100 500 1000 2000}"

TARGET_ADDR=":9099"
TARGET_URL="http://127.0.0.1:9099"
BB_ADDR=":9115"
BBPROBE="http://127.0.0.1:9115/probe?module=http_2xx&target=${TARGET_URL}"
SENT_ADDR=":8080"
SENT_METRICS="http://127.0.0.1:8080/metrics"

mkdir -p "$CACHE" "$BENCH/run" "$BENCH/logs"
RESULTS="$BENCH/results.txt"
: > "$RESULTS"
log() { echo "$@" | tee -a "$RESULTS"; }
die() { echo "error: $*" >&2; exit 1; }

# --- provisioning ----------------------------------------------------------

# sentinel binary
SENT="$REPO/bin/sentinel"
echo "building sentinel ..." >&2
make -C "$REPO" build >/dev/null || die "make build failed"
[ -x "$SENT" ] || die "sentinel binary not found at $SENT"

# benchtool
BT="$CACHE/benchtool"
echo "building benchtool ..." >&2
( cd "$BENCH" && go build -o "$BT" . ) || die "benchtool build failed"

# blackbox_exporter (pinned release)
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in x86_64|amd64) arch=amd64;; arm64|aarch64) arch=arm64;; *) die "unsupported arch $arch";; esac
BB_DIR="$CACHE/blackbox_exporter-${BB_VERSION}.${os}-${arch}"
BB="$BB_DIR/blackbox_exporter"
if [ ! -x "$BB" ]; then
  url="https://github.com/prometheus/blackbox_exporter/releases/download/v${BB_VERSION}/blackbox_exporter-${BB_VERSION}.${os}-${arch}.tar.gz"
  echo "downloading blackbox_exporter ${BB_VERSION} (${os}-${arch}) ..." >&2
  curl -sSL -o "$CACHE/bb.tgz" "$url" || die "download failed: $url"
  tar xzf "$CACHE/bb.tgz" -C "$CACHE" || die "extract failed"
fi
[ -x "$BB" ] || die "blackbox_exporter not found at $BB"

# --- helpers ---------------------------------------------------------------

cleanup() { pkill -f "$BT" 2>/dev/null; pkill -f "$SENT" 2>/dev/null; pkill -f "$BB" 2>/dev/null; }
trap cleanup EXIT
cleanup; sleep 0.5

# ps cputime -> seconds  ([[H:]M]M:SS.ss)
cputime_s() {
  ps -o cputime= -p "$1" 2>/dev/null | tr -d ' ' | awk -F: '
    { n=NF; s=$n; m=(n>=2?$(n-1):0); h=(n>=3?$(n-2):0); printf "%.2f", h*3600+m*60+s }'
}
rss_kb() { ps -o rss= -p "$1" 2>/dev/null | tr -d ' '; }

# sample_proc PID WINDOW -> "cpu_pct peak_rss_mb mean_rss_mb"
sample_proc() {
  local pid=$1 win=$2 c0 c1 r samples=()
  c0=$(cputime_s "$pid")
  local end=$((SECONDS+win))
  while [ $SECONDS -lt $end ]; do
    r=$(rss_kb "$pid"); [ -n "$r" ] && samples+=("$r")
    sleep 1
  done
  c1=$(cputime_s "$pid")
  awk -v c0="$c0" -v c1="$c1" -v win="$win" 'BEGIN{printf "%.1f ", (c1-c0)/win*100}'
  printf '%s\n' "${samples[@]}" | awk '{if($1>mx)mx=$1; s+=$1; n++} END{printf "%.1f %.1f", mx/1024, s/n/1024}'
}

p50_of() { awk -F'p50=' '/latency/{split($2,a," ");print a[1]}'; }

# --- shared target ---------------------------------------------------------

"$BT" target -addr "$TARGET_ADDR" >"$BENCH/logs/target.log" 2>&1 &
sleep 0.5

log "=== ENV ==="
log "date $(date -u +%FT%TZ)  host $(uname -mrs)  cpus $( (sysctl -n hw.ncpu 2>/dev/null) || nproc )"
log "sentinel $("$SENT" -version 2>&1 | head -1)"
log "blackbox $("$BB" --version 2>&1 | head -1)"
log "interval=${INTERVAL_S}s warmup=${WARMUP_S}s window=${WINDOW_S}s targets=${NS[*]}"
log ""

# ============================ DIMENSION A ============================
log "=== DIMENSION A: per-probe engine cost (local target) ==="
"$BB" --config.file="$BENCH/blackbox.yml" --web.listen-address="$BB_ADDR" >"$BENCH/logs/bb_A.log" 2>&1 &
BBPID=$!
sleep 1
log "[blackbox] 3000 sequential probes:"
"$BT" bb-probe -url "$BBPROBE" -n 3000 -c 1 | tee -a "$RESULTS"
kill "$BBPID" 2>/dev/null; wait "$BBPID" 2>/dev/null
log ""
log "[sentinel] BenchmarkProbe (in-process, local httptest):"
( cd "$REPO" && go test -run '^$' -bench '^BenchmarkProbe$' -benchmem -benchtime 3000x ./internal/probe/http/ 2>&1 \
  | grep -E 'Benchmark|ns/op|allocs' ) | tee -a "$RESULTS"
log ""

# ============================ DIMENSION B ============================
log "=== DIMENSION B: steady-state scale (aggregate probe rate = N/${INTERVAL_S}s) ==="
log ""
printf "%-6s | %-32s | %-32s\n" "N" "SENTINEL (active/decoupled)" "BLACKBOX (probe-on-scrape)" | tee -a "$RESULTS"
printf "%-6s | %-8s %-7s %-7s %-6s | %-8s %-7s %-7s\n" "" "cpu%" "peakMB" "meanMB" "scr_ms" "cpu%" "peakMB" "lat_ms" | tee -a "$RESULTS"

for N in "${NS[@]}"; do
  RATE=$(( N / INTERVAL_S )); [ "$RATE" -lt 1 ] && RATE=1

  # ---------- SENTINEL ----------
  "$BT" genconfig -n "$N" -url "$TARGET_URL" -interval "${INTERVAL_S}s" -timeout 3s -out "$BENCH/run/s${N}.yaml" 2>/dev/null
  "$SENT" -config "$BENCH/run/s${N}.yaml" -listen "$SENT_ADDR" -log-level error >"$BENCH/logs/sent_${N}.log" 2>&1 &
  SPID=$!
  sleep "$WARMUP_S"
  SENT_SAMP=$(sample_proc "$SPID" "$WINDOW_S")
  SCR=$("$BT" scrape -url "$SENT_METRICS" -n 30 2>/dev/null | p50_of)
  kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null
  sleep 0.5

  # ---------- BLACKBOX ----------
  "$BB" --config.file="$BENCH/blackbox.yml" --web.listen-address="$BB_ADDR" >"$BENCH/logs/bb_${N}.log" 2>&1 &
  BPID=$!
  sleep 2
  "$BT" bb-load -url "$BBPROBE" -rate "$RATE" -dur $((WINDOW_S+4)) >"$BENCH/logs/bbload_${N}.txt" 2>&1 &
  LPID=$!
  sleep 2
  BB_SAMP=$(sample_proc "$BPID" "$WINDOW_S")
  wait "$LPID" 2>/dev/null
  BLAT=$(p50_of <"$BENCH/logs/bbload_${N}.txt")
  kill "$BPID" 2>/dev/null; wait "$BPID" 2>/dev/null
  sleep 0.5

  read -r SC_CPU SC_PK SC_MN <<<"$SENT_SAMP"
  read -r BB_CPU BB_PK _ <<<"$BB_SAMP"
  printf "%-6s | %-8s %-7s %-7s %-6s | %-8s %-7s %-7s\n" \
    "$N" "$SC_CPU" "$SC_PK" "$SC_MN" "${SCR:-?}" "$BB_CPU" "$BB_PK" "${BLAT:-?}" | tee -a "$RESULTS"
done

log ""
log "rate note: at N targets / ${INTERVAL_S}s interval both systems perform N/${INTERVAL_S} probes/s."
log "DONE"