#!/usr/bin/env bash
# Two consecutive UTC days → reviewable network-contact signals.
# Day 1 stores a RIB snapshot only; day 2 diffs and writes inbox.jsonl.
#
# Usage:
#   ./scripts/run-local-review.sh                 # UTC today-2 and today-1
#   ./scripts/run-local-review.sh 2024-06-01 2024-06-02
#
# Review: data/daily-review/signals/inbox.jsonl
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="${BGP_DAILY_STATE:-$ROOT/data/daily-review}"
export BGP_DAILY_STATE="$STATE"

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  cat <<'EOF'
Two consecutive UTC days → reviewable network-contact signals.
Day 1 stores a RIB snapshot only; day 2 diffs and writes inbox.jsonl.

Usage:
  ./scripts/run-local-review.sh
  ./scripts/run-local-review.sh 2024-06-01 2024-06-02

Review: data/daily-review/signals/inbox.jsonl
EOF
  exit 0
fi

if [ $# -eq 0 ]; then
  # UTC today−2 / today−1 (portable; bash 3.2 / GNU date / BSD date).
  eval "$(python3 - <<'PY'
from datetime import datetime, timedelta, timezone
today = datetime.now(timezone.utc).date()
print(f'DAY1={(today - timedelta(days=2)).isoformat()}')
print(f'DAY2={(today - timedelta(days=1)).isoformat()}')
PY
)"
elif [ $# -eq 2 ]; then
  DAY1="$1"
  DAY2="$2"
else
  echo "usage: $0 [YYYY-MM-DD YYYY-MM-DD]" >&2
  exit 1
fi

echo "$DAY1" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' || {
  echo "bad day1: $DAY1" >&2
  exit 1
}
echo "$DAY2" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' || {
  echo "bad day2: $DAY2" >&2
  exit 1
}

test -x "${BGP_ANALYZER_BIN:-$ROOT/target/release/bgp-analyzer}" || {
  echo "missing release binary — build with: cargo build -p bgp-analyzer-cli --release" >&2
  exit 1
}

echo "== local review =="
echo "state=$STATE"
echo "day1=$DAY1 (snapshot only if empty state)"
echo "day2=$DAY2 (diff → signals)"

"$ROOT/scripts/run-daily-signals.sh" "$DAY1"
"$ROOT/scripts/run-daily-signals.sh" "$DAY2"

INBOX="$STATE/signals/inbox.jsonl"
DAYFILE="$STATE/signals/signals-${DAY2}.jsonl"
echo
echo "== review these files =="
echo "inbox:  $INBOX"
if [ -f "$INBOX" ]; then
  echo "lines:  $(wc -l < "$INBOX" | tr -d ' ')"
else
  echo "lines:  0 (no signals emitted — sparse day or no prior snapshot pair)"
fi
echo "day:    $DAYFILE"
echo
if [ -f "$INBOX" ]; then
  echo "== first signals (pretty JSONL) =="
  python3 - "$INBOX" <<'PY'
import json, sys
from pathlib import Path
lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
for i, line in enumerate(lines[:3], 1):
    print(f"--- signal {i} ---")
    print(json.dumps(json.loads(line), indent=2))
PY
  echo
  echo "hint: python3 -c \"import json; [print(json.dumps(json.loads(l), indent=2)) for l in open('$INBOX')]\""
fi
