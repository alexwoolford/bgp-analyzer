# Backtest then daily distill

Validate behavior offline on consecutive RIB day dumps, then run a thin daily job that emits sparse network-contact signals.

Large downloads stay under gitignored `data/`.

## Backtest

Fetches RouteViews (or other collector) **RIB** dumps for `--days` consecutive calendar days, diffs each consecutive pair, writes events, and aggregates ASN-pair features.

```bash
cargo run -p bgp-analyzer-cli --release -- backtest \
  --start 2022-01-01 \
  --days 30 \
  --collector route-views2 \
  --org-map data/org-map/current \
  --glue fixtures/glue-asns.txt \
  --out-dir data/backtest/2022-01
```

Outputs under `--out-dir`:

| Path | Contents |
|------|----------|
| `snapshots/rib-YYYY-MM-DD.json` | Day RIB origin snapshot (`as_of` = window end) |
| `events/events-D1-to-D2.jsonl` | Per-day-pair full diffs |
| `events/all-events.jsonl` | Concatenated events |
| `pair-features.jsonl` | ASN-pair persistence / prefixes_moved / score |

Re-run with `--skip-fetch` to reuse snapshots already on disk.

**Attribution caveat:** PeeringDB is crawl-time, not historical. Prefer a dated org map near the study window when available.

## Pair features

Each row ranks undirected ASN contact:

- `prefixes_moved`, `prefix_move_days`, `new_adj_days`, `upstream_converge_days`
- `persistence_days` (first→last span)
- `score` — triage heuristic, **not** a deal probability

Optional:

```bash
bgp-analyzer eval \
  --events data/backtest/2022-01/events/all-events.jsonl \
  --features data/backtest/2022-01/pair-features.jsonl \
  --cases fixtures/eval/cases.jsonl
```

## Daily distill

```bash
./scripts/run-daily-signals.sh
# or pin a UTC day:
./scripts/run-daily-signals.sh 2022-01-02
```

See [DAILY_OPS.md](DAILY_OPS.md).

- First run with no prior snapshot only stores today (no events).
- Signals: `signals/signals-YYYY-MM-DD.jsonl` (`source=bgp_analyzer`, `kind=network_contact`) + `signals/inbox.jsonl`

Evaluation headline: [LEAD_LAG_VERDICT.md](LEAD_LAG_VERDICT.md).
