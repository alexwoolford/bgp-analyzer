# BGP M&A network-contact signals

## What it delivers

Emit **attributable contact** between two **non-glue** organizations’ networks, with **ASN** / **org** / optional **domains** on each event. A pair is emitted only when **both** ASNs map to an org, neither is glue or leasing, and they are not the same PeeringDB org or the same corporate family (shared registrable domain).

The **daily product** is sparse **`prefix_move`** (default: ≥2 prefixes on the same ASN pair that day). Upstream convergence, new adjacency, and footprint steps exist on the diff and on `--full` / backtest; production `run-daily-signals.sh` does not pass `--full`, so those kinds are not upserted to `network_contact`.

This repo ships a **network-contact** feed, not a ranked deal list.

Offline evaluation found the signal **weak alone** for M&A prediction—see [LEAD_LAG_VERDICT.md](LEAD_LAG_VERDICT.md). Treat `score` as **triage**, not P(deal).

Ops: [DAILY_OPS.md](DAILY_OPS.md). Org map vs change stream: [ORG_MAP.md](ORG_MAP.md). Historical windows: [BACKTEST.md](BACKTEST.md).

Valley-free / RPKI leak detection remains an optional cyber side channel (`bgp-analyzer analyze`).

Daily sparse defaults are frozen: `prefix_move` ≥2 prefixes per pair per day; other kinds off unless `--full`.

## How pairs are found (rolling day diff)

Production does **not** need a long history in the hot path. Each day:

1. Keep yesterday’s RIB snapshot
2. Fetch today’s RIB → origin-collapsed snapshot (optionally focus-filtered to subject ASNs)
3. Diff `T−1` vs `T` → events → sparse filter (default: `prefix_move` ≥2) → clean (glue / leasing / unattributed / same-org / same-family)
4. Update ~30d pair state; upsert `network_contact` in the work sqlite; write `signals/signals-YYYY-MM-DD.jsonl` after commit (intermediate `events/` JSONL only with `--debug-jsonl`)

Operator entrypoint: `./scripts/run-daily-signals.sh` (see [DAILY_OPS.md](DAILY_OPS.md)).

## Subjects vs glue

- **Glue ASNs** ([`fixtures/glue-asns.txt`](../fixtures/glue-asns.txt)): hyperscalers (including common satellite ASNs), CDNs, Tier-1 transit, large eyeballs. Path context only. A contact pair is dropped if **either** ASN is glue — not only glue↔glue.
- **Subjects**: ASNs from the PeeringDB-built org map that pass [`SubjectHeuristics`](../crates/bgp-map/src/lib.rs). Crawl-time filtering only drops glue (`prefix_count` is unknown). Daily `--focus-from-org-map` applies **today’s RIB origin prefix counts** to those heuristics (drop stubs and >5k-prefix networks) and retains snapshot prefixes whose **origin** is in the focus set (not “any AS_PATH hop”).

## Mapping

[`OrgMap`](../crates/bgp-map/src/lib.rs) via `bgp-analyzer build-org-map`:

- PeeringDB `net` + `org` (ASN, name, website → domains). Each HTTP crawl paginates all of `/net`; sqlite/`_outbox` commit is change-aware. This is attribution reference data, not the change stream ([ORG_MAP.md](ORG_MAP.md)).
- Optional `--extra-domains` enrichment on `ma-diff` (watchlist file; not a gate)
- PeeringDB is a live registry: each crawl writes `org_map_runs.built_at` (`utc_iso`); dated JSON is a local copy. Daily loads live `orgs` from sqlite and does not crawl.

Attributes on each signal: `asn_a` / `asn_b`, `domains_a` / `domains_b`, `org_a` / `org_b` (both org ids are required on the daily emit).

PeeringDB `org_id` is not a corporate parent. Same-family clean uses a shared registrable domain (eTLD+1) across the two orgs, plus the glue list for hyperscaler satellites. CAIDA `as2org` is not in this repo.

## Events ([`bgp-ma`](../crates/bgp-ma/src/lib.rs))

| Kind | Daily default | Meaning |
|------|---------------|---------|
| `prefix_move` | **yes** (≥2 prefixes / pair / day) | Same prefix, origin ASN changes involving ≥1 subject; neither side glue |
| `upstream_converge` | `--full` / backtest only | Subject origin gains a new immediate upstream tied to another org/subject |
| `new_adj` | `--full` / backtest only | New AS_PATH adjacency between two non-glue subject ASNs |
| `footprint_step` | `--full` / backtest only | Large change in prefix count for a subject origin |

Snapshot `as_of` is the BGP window **`--end`**, not wall-clock build time. When several collector peers announce the same prefix, the snapshot keeps the peer with the **longest** AS_PATH (more adjacency context; not shortest-path selection).

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
# optional: --debug-jsonl  (intermediate events/ JSONL)
# optional: --full         (also emit new_adj / upstream_converge / footprint_step)

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
