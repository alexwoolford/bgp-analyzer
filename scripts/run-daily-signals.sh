#!/usr/bin/env bash
# Quiet daily BGP network-contact signal emitter.
# Org map comes from work sqlite (no PeeringDB crawl). score is triage, not P(deal).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BGP_ANALYZER_BIN:-$ROOT/target/release/bgp-analyzer}"
STATE="${BGP_DAILY_STATE:-$ROOT/data/daily}"
GLUE="${BGP_GLUE:-$ROOT/fixtures/glue-asns.txt}"
# Overlay is opt-in (dev/eval). Production env must not set this.
OVERLAY="${BGP_ORG_MAP_OVERLAY:-}"
COLLECTOR="${BGP_COLLECTOR:-route-views2}"
MAX_AGE_DAYS="${ORG_MAP_MAX_AGE_DAYS:-14}"
LOCK="${BGP_DAILY_LOCK:-$STATE/.daily.lock}"

DATE_ARG=()
if echo "${1:-}" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
  DATE_ARG=(--date "$1")
  shift
fi

test -x "$BIN" || {
  echo "missing $BIN — build with: cargo build -p bgp-analyzer-cli --release" >&2
  exit 1
}
test -f "$GLUE" || {
  echo "missing glue $GLUE" >&2
  exit 1
}

mkdir -p "$STATE"

acquire_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK"
    if ! flock -n 9; then
      echo "daily signals already running (lock $LOCK)" >&2
      exit 1
    fi
  else
    if ! mkdir "$LOCK.d" 2>/dev/null; then
      echo "daily signals already running (lock $LOCK.d)" >&2
      exit 1
    fi
    trap 'rmdir "$LOCK.d" 2>/dev/null || true' EXIT
  fi
}
acquire_lock

echo "== daily network-contact signals =="
echo "bin=$BIN state=$STATE sqlite=$STATE/bgp-analyzer.sqlite"

# Bash 3.2 + set -u: empty arrays error on "${arr[@]}". Build argv explicitly.
CMD=(
  "$BIN" daily
  --state-dir "$STATE"
  --collector "$COLLECTOR"
  --glue "$GLUE"
  --focus-from-org-map
  --retain-days 7
  --pair-state-days 30
  --min-prefix-moves 2
  --org-map-max-age-days "$MAX_AGE_DAYS"
)
if [ ${#DATE_ARG[@]} -gt 0 ]; then
  CMD+=("${DATE_ARG[@]}")
fi
if [ -n "$OVERLAY" ] && [ -f "$OVERLAY" ]; then
  CMD+=(--org-map-overlay "$OVERLAY")
fi
if [ "$#" -gt 0 ]; then
  CMD+=("$@")
fi
"${CMD[@]}"

if [ ${#DATE_ARG[@]} -ge 2 ]; then
  DAY="${DATE_ARG[1]}"
else
  DAY="$(date -u +%Y-%m-%d)"
fi
echo "sqlite  → $STATE/bgp-analyzer.sqlite"
echo "signals → $STATE/signals/signals-${DAY}.jsonl"
echo "inbox   → $STATE/signals/inbox.jsonl"
