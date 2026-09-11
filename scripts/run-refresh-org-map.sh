#!/usr/bin/env bash
# Weekly PeeringDB org-map refresh: sqlite SoR + dated JSON copy + current symlink.
# Daily signal jobs read live orgs from $BGP_DAILY_STATE/bgp-analyzer.sqlite (no crawl).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BGP_ANALYZER_BIN:-$ROOT/target/release/bgp-analyzer}"
GLUE="${BGP_GLUE:-$ROOT/fixtures/glue-asns.txt}"
STATE="${BGP_DAILY_STATE:-$ROOT/data/daily}"
ORG_MAP_DIR="${BGP_ORG_MAP_DIR:-$ROOT/data/org-map}"
RETAIN="${BGP_ORG_MAP_RETAIN:-4}"
LOCK="${BGP_ORG_MAP_LOCK:-$ORG_MAP_DIR/.refresh.lock}"
DATE_UTC="$(date -u +%Y-%m-%d)"

test -x "$BIN" || {
  echo "missing $BIN — build with: cargo build -p bgp-analyzer-cli --release" >&2
  exit 1
}
test -f "$GLUE" || {
  echo "missing glue $GLUE" >&2
  exit 1
}

mkdir -p "$ORG_MAP_DIR" "$STATE"

acquire_lock() {
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK"
    if ! flock -n 9; then
      echo "org-map refresh already running (lock $LOCK)" >&2
      exit 1
    fi
  else
    # Portable fallback (macOS): mkdir is atomic.
    if ! mkdir "$LOCK.d" 2>/dev/null; then
      echo "org-map refresh already running (lock $LOCK.d)" >&2
      exit 1
    fi
    trap 'rmdir "$LOCK.d" 2>/dev/null || true' EXIT
  fi
}
acquire_lock

OUT="$ORG_MAP_DIR/org-map-peeringdb-${DATE_UTC}.json"
TMP="${OUT}.tmp.$$"

echo "== refresh org-map =="
echo "bin=$BIN state=$STATE out=$OUT"

"$BIN" build-org-map \
  --glue "$GLUE" \
  --state-dir "$STATE" \
  --output "$TMP"

mv -f "$TMP" "$OUT"

# Atomic symlink update: new link then rename over current.
ln -sfn "$(basename "$OUT")" "$ORG_MAP_DIR/current.tmp"
mv -f "$ORG_MAP_DIR/current.tmp" "$ORG_MAP_DIR/current"

# Retain newest N dated maps (bash 3.2 portable).
n=0
# shellcheck disable=SC2012
for f in $(ls -1t "$ORG_MAP_DIR"/org-map-peeringdb-*.json 2>/dev/null); do
  n=$((n + 1))
  if [ "$n" -gt "$RETAIN" ]; then
    rm -f "$f"
  fi
done

CUR_TARGET="$(readlink "$ORG_MAP_DIR/current" 2>/dev/null || true)"
echo "sqlite  → $STATE/bgp-analyzer.sqlite"
echo "current → $ORG_MAP_DIR/current -> ${CUR_TARGET:-?}"
