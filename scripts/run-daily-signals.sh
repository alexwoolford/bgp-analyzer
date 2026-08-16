#!/usr/bin/env bash
# Quiet daily BGP network-contact signal emitter.
# Uses a cached PeeringDB org map (no crawl). score is triage, not P(deal).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BGP_ANALYZER_BIN:-$ROOT/target/release/bgp-analyzer}"
STATE="${BGP_DAILY_STATE:-$ROOT/data/daily}"
ORG_MAP_DIR="${BGP_ORG_MAP_DIR:-$ROOT/data/org-map}"
# Prefer symlink from weekly refresh; fall back to legacy undated path for local smoke.
if [ -n "${BGP_ORG_MAP:-}" ]; then
  ORG="$BGP_ORG_MAP"
elif [ -e "$ORG_MAP_DIR/current" ]; then
  ORG="$ORG_MAP_DIR/current"
elif [ -f "$ROOT/data/org-map-peeringdb.json" ]; then
  ORG="$ROOT/data/org-map-peeringdb.json"
else
  ORG="$ORG_MAP_DIR/current"
fi
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

if [ ! -e "$ORG" ]; then
  echo "missing org map $ORG — run ./scripts/run-refresh-org-map.sh first" >&2
  exit 1
fi

# Resolve symlink target when possible (Linux readlink -f / realpath).
ORG_REAL="$ORG"
if command -v realpath >/dev/null 2>&1; then
  ORG_REAL="$(realpath "$ORG")"
elif readlink -f "$ORG" >/dev/null 2>&1; then
  ORG_REAL="$(readlink -f "$ORG")"
fi

# Age gate: prefer built_at in JSON; fall back to file mtime.
python3 - "$ORG_REAL" "$MAX_AGE_DAYS" <<'PY'
import json, os, sys, time
from datetime import datetime, timezone

path, max_age = sys.argv[1], int(sys.argv[2])
built = None
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    built = data.get("built_at")
except Exception as e:
    print(f"org-map age check: failed to read {path}: {e}", file=sys.stderr)
    sys.exit(1)

if built:
    try:
        # Rust chrono may emit nanoseconds; Python <3.11 fromisoformat is picky.
        s = built.replace("Z", "+00:00")
        if "." in s:
            head, rest = s.split(".", 1)
            frac = ""
            tz = ""
            for i, ch in enumerate(rest):
                if ch.isdigit():
                    frac += ch
                else:
                    tz = rest[i:]
                    break
            frac = (frac + "000000")[:6]
            s = f"{head}.{frac}{tz}"
        ts = datetime.fromisoformat(s)
        age_days = (datetime.now(timezone.utc) - ts.astimezone(timezone.utc)).total_seconds() / 86400.0
    except Exception as e:
        print(f"org-map age check: bad built_at={built!r}: {e}", file=sys.stderr)
        sys.exit(1)
else:
    age_days = (time.time() - os.path.getmtime(path)) / 86400.0
    print(f"org-map age check: no built_at; using mtime age={age_days:.1f}d", file=sys.stderr)

if age_days > max_age:
    print(
        f"org map too old ({age_days:.1f}d > {max_age}d): {path}\n"
        f"  refresh with: ./scripts/run-refresh-org-map.sh",
        file=sys.stderr,
    )
    sys.exit(1)
print(f"org-map age ok ({age_days:.1f}d ≤ {max_age}d)")
PY

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
echo "bin=$BIN state=$STATE org=$ORG"

# Bash 3.2 + set -u: empty arrays error on "${arr[@]}". Build argv explicitly.
CMD=(
  "$BIN" daily
  --state-dir "$STATE"
  --collector "$COLLECTOR"
  --org-map "$ORG"
  --glue "$GLUE"
  --focus-from-org-map
  --retain-days 7
  --pair-state-days 30
  --min-prefix-moves 2
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
echo "signals → $STATE/signals/signals-${DAY}.jsonl"
echo "inbox   → $STATE/signals/inbox.jsonl"
