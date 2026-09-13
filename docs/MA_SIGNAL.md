# BGP M&A network-contact signals

## What it delivers

Emit **attributable contact** between two **non-glue** organizations’ networks (prefix migration, upstream convergence, new adjacency, footprint steps), with **ASN** / **org** / optional **domains** on each event.

This repo ships a finished **network-contact** feed.

Offline evaluation found the signal **weak alone** for M&A prediction—see [LEAD_LAG_VERDICT.md](LEAD_LAG_VERDICT.md). Treat `score` as **triage**, not P(deal).

Ops: [DAILY_OPS.md](DAILY_OPS.md). Org map vs change stream: [ORG_MAP.md](ORG_MAP.md). Historical windows: [BACKTEST.md](BACKTEST.md).

Valley-free / RPKI leak detection remains an optional cyber side channel (`bgp-analyzer analyze`).

Daily sparse defaults are frozen (e.g. `prefix_move` ≥2 prefixes per pair per day).

## How pairs are found (rolling day diff)

Production does **not** need a long history in the hot path. Each day:

1. Keep yesterday’s RIB snapshot
2. Fetch today’s RIB → origin-collapsed snapshot (optionally focus-filtered to subject ASNs)
3. Diff `T−1` vs `T` → events → sparse filter → same-org/leasing clean
4. Update ~30d pair state; upsert `network_contact` in the work sqlite; write `signals/signals-YYYY-MM-DD.jsonl` after commit

Operator entrypoint: `./scripts/run-daily-signals.sh` (see [DAILY_OPS.md](DAILY_OPS.md)).

## Subjects vs glue

- **Glue ASNs** ([`fixtures/glue-asns.txt`](../fixtures/glue-asns.txt)): hyperscalers, CDNs, Tier-1 transit, large eyeballs. Path context only.
- **Subjects**: ASNs from the PeeringDB-built org map that pass [`SubjectHeuristics`](../crates/bgp-map/src/lib.rs). Crawl-time filtering only drops glue (`prefix_count` is unknown), so the stored spine is broader than a prefix-size mid-market cut. Daily `--focus-from-org-map` uses that spine.

## Mapping

[`OrgMap`](../crates/bgp-map/src/lib.rs) via `bgp-analyzer build-org-map`:

- PeeringDB `net` + `org` (ASN, name, website → domains). Each HTTP crawl paginates all of `/net`; sqlite/`_outbox` commit is change-aware. This is attribution reference data, not the change stream ([ORG_MAP.md](ORG_MAP.md)).
- Optional `--extra-domains` enrichment on `ma-diff` (watchlist file; not a gate)
- PeeringDB is a live registry: each crawl writes `org_map_runs.built_at` (`utc_iso`); dated JSON is a local copy. Daily loads live `orgs` from sqlite and does not crawl.

Attributes on each signal: `asn_a` / `asn_b`, `domains_a` / `domains_b`, `org_a` / `org_b`.

## Events ([`bgp-ma`](../crates/bgp-ma/src/lib.rs))

| Kind | Meaning |
|------|---------|
| `prefix_move` | Same prefix, origin ASN changes involving ≥1 subject |
| `upstream_converge` | Subject origin gains a new immediate upstream tied to another org/subject |
| `new_adj` | New AS_PATH adjacency between two non-glue subject ASNs |
| `footprint_step` | Large change in prefix count for a subject origin |

Snapshot `as_of` is the BGP window **`--end`**, not wall-clock build time.

## CLI

```bash
bgp-analyzer build-org-map \
  --glue fixtures/glue-asns.txt \
  --state-dir data/daily \
  --output data/org-map/org-map-peeringdb-$(date -u +%F).json

bgp-analyzer backtest \
  --start 2022-01-01 --days 30 \
  --org-map data/org-map/current \
  --glue fixtures/glue-asns.txt \
  --out-dir data/backtest/2022-01

bgp-analyzer daily \
  --state-dir data/daily \
  --glue fixtures/glue-asns.txt \
  --focus-from-org-map

./scripts/run-refresh-org-map.sh
./scripts/run-daily-signals.sh
```

Deploy: [DAILY_OPS.md](DAILY_OPS.md) (`deploy/install.sh` + systemd timers).

Single-pair tooling: `snapshot` (default `--mode rib`) + `ma-diff`. Debug-only: `--mode updates` / `--max-updates`.

Optional hit/miss scoring against a local cases JSONL:

```bash
bgp-analyzer eval \
  --events data/backtest/2022-01/events/all-events.jsonl \
  --features data/backtest/2022-01/pair-features.jsonl \
  --cases fixtures/eval/cases.jsonl
```
