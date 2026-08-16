# Eval cases

Optional JSONL cases for `bgp-analyzer eval` (hit/miss against backtest events and pair features).

One JSON object per line (`#` comments allowed):

- `id`, `asn_a`, `asn_b` (optional), `window_start`, `window_end`
- `expect_kind` — e.g. `prefix_move`, `footprint_step`
- `expect_hit` — default `true`
- `notes` — free text

```bash
bgp-analyzer eval \
  --events data/backtest/2022-01/events/all-events.jsonl \
  --features data/backtest/2022-01/pair-features.jsonl \
  --cases fixtures/eval/cases.jsonl
```
