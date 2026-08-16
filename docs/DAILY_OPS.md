# BGP daily network-contact signals (ops)

## Product

This repo emits **BGP network-contact signals**: attributable contact between non-glue organizations’ networks (prefix moves, new adjacency, upstream convergence, footprint steps), with ASN / org / domain attributes.

`score` is a **triage heuristic**, not a calibrated deal probability. Offline lead-lag work found low precision when treating high scores as M&A leads — do not rank “BGP first” for deal discovery. See [LEAD_LAG_VERDICT.md](LEAD_LAG_VERDICT.md).

## Diff mechanics

Quiet production is a **rolling day pair**:

1. Fetch (or reuse) today’s RouteViews RIB → origin-collapsed snapshot
2. Diff vs the prior retained snapshot (`T−1` vs `T`)
3. Sparse-filter (`prefix_move` with ≥2 prefixes per ASN pair by default)
4. Drop same-org multi-ASN and leasing/marketplace ASNs
5. Update 30-day rolling pair state (persistence)
6. Emit versioned signals (`kind=network_contact`)

Long historical backtests (monthly RIBs) are for **evaluation**, not the hot path. Local quarantine and downloads stay under gitignored `data/` — never in the product tree.

## Org map (PeeringDB reference data)

The ASN↔org↔domain map is **reference data**. PeeringDB changes over time; a full crawl is polite but not free.

| Cadence | Job | Behavior |
|---------|-----|----------|
| **Weekly** | `./scripts/run-refresh-org-map.sh` | Crawl PeeringDB → dated JSON + `current` symlink |
| **Daily** | `./scripts/run-daily-signals.sh` | Use cached map only; **refuse** if missing or older than `ORG_MAP_MAX_AGE_DAYS` (default 14) |

Daily does **not** crawl PeeringDB. Overlay (`BGP_ORG_MAP_OVERLAY`) is opt-in for local eval — do not set it in production.

## Local review (eyeball a run)

Do **not** look at cyber `alerts.jsonl`. Product output is the daily signal inbox.

```bash
cargo build -p bgp-analyzer-cli --release

# Org map once if you do not already have a fresh map (or reuse data/org-map-peeringdb.json)
./scripts/run-refresh-org-map.sh

# Two consecutive UTC days (needs network for RouteViews RIBs)
./scripts/run-local-review.sh
# or pin dates:
./scripts/run-local-review.sh 2024-06-01 2024-06-02
```

Review:

- `data/daily-review/signals/inbox.jsonl` — append-only feed (preferred)
- `data/daily-review/signals/signals-YYYY-MM-DD.jsonl` — that day’s emit

Day 1 only stores a snapshot; day 2 diffs and writes signals. Expect real RIB downloads (minutes).

## Local run (ongoing)

```bash
cargo build -p bgp-analyzer-cli --release

./scripts/run-refresh-org-map.sh   # once (or weekly)
./scripts/run-daily-signals.sh     # first day stores snapshot only
./scripts/run-daily-signals.sh     # next UTC day emits signals
```

Env overrides: `BGP_ANALYZER_BIN`, `BGP_DAILY_STATE`, `BGP_ORG_MAP` / `BGP_ORG_MAP_DIR`, `BGP_GLUE`, `BGP_ORG_MAP_OVERLAY` (opt-in), `BGP_COLLECTOR`, `ORG_MAP_MAX_AGE_DAYS`.

Default enables `--focus-from-org-map` so snapshots keep subject ASNs (affordable quiet runs).

## Deploy (systemd, recommended)

### Deploy decision

**Prefer git clone (or a tagged checkout) + [`deploy/install.sh`](../deploy/install.sh) + systemd timers.** Do not ship a dnf/RPM package for the first production hosts.

This is a lightweight batch emitter (daily RIB diff, weekly PeeringDB crawl), not a multi-host daemon fleet. Clone → build release → install under `/opt` with state in `/var/lib` is enough. A dnf package (private repo, signing, buildroot) can wait until you need many identical hosts or hosts without a Rust toolchain; then ship a **prebuilt** binary RPM that installs the same layout.

Do **not** run production from a developer checkout under `$HOME` with ad-hoc cron. Use the `/opt` + `/var/lib` split below.

Host prerequisites: outbound HTTPS (BGPKIT broker, RouteViews, PeeringDB), Rust toolchain on the box (or copy a prebuilt binary into place), and disk for RIB snapshots (tens of GB over time; pruned via `--retain-days`).

### Install

Lightweight install under `/opt/bgp-analyzer` with state in `/var/lib/bgp-analyzer`:

```bash
git clone <repo-url> bgp-analyzer && cd bgp-analyzer
# optional: git checkout <tag>
sudo ./deploy/install.sh
```

Units shipped in [`deploy/systemd/`](../deploy/systemd/):

| Unit | Schedule |
|------|----------|
| `bgp-org-map.timer` | Sunday 01:00 UTC (weekly PeeringDB refresh) |
| `bgp-signals.timer` | Daily 02:30 UTC |

Config: `/opt/bgp-analyzer/etc/bgp-analyzer.env` (from [`deploy/bgp-analyzer.env.example`](../deploy/bgp-analyzer.env.example)).

```bash
journalctl -u bgp-signals.service -u bgp-org-map.service -f
systemctl list-timers 'bgp-*'
systemctl start bgp-org-map.service   # manual refresh
systemctl start bgp-signals.service   # manual daily
```

Wrappers use `flock` (Linux) so overlapping timer runs fail fast instead of double-writing state.

### Layout

```
/opt/bgp-analyzer/
  bin/bgp-analyzer
  scripts/run-daily-signals.sh
  scripts/run-refresh-org-map.sh
  fixtures/glue-asns.txt
  etc/bgp-analyzer.env
/var/lib/bgp-analyzer/           # snapshots, events, pair-state, signals
/var/lib/bgp-analyzer/org-map/
  org-map-peeringdb-YYYY-MM-DD.json
  current -> …
```

Upgrades: `git pull` (or new tag) → re-run `sudo ./deploy/install.sh` (env file at `/opt/bgp-analyzer/etc/bgp-analyzer.env` is preserved if already present). Review output: `/var/lib/bgp-analyzer/signals/inbox.jsonl`.

## Outputs (reviewable)

Under the state dir (`data/daily/` locally, `/var/lib/bgp-analyzer/` in production — gitignored):

| Path | Purpose |
|------|---------|
| `snapshots/rib-YYYY-MM-DD.json` | Rolling RIB origin snapshots |
| `events/events-YYYY-MM-DD.jsonl` | Sparse day events |
| `events/pair-features-YYYY-MM-DD.cleaned.jsonl` | Cleaned pairs for the day |
| `pair-state.json` | ~30d persistence store |
| `signals/signals-YYYY-MM-DD.jsonl` | Signal envelope |
| `signals/inbox.jsonl` | Append-only human review feed |

### Signal envelope (`schema_version: 1`)

- `source`: `bgp_analyzer`
- `kind`: `network_contact`
- `as_of` / `prior_as_of`
- Attributes: `asn_a`/`asn_b`, `org_a`/`org_b`, `domains_a`/`domains_b`
- `prefixes_moved`, day counts, `persistence_days`, triage `score`

## Limits

- Only ASN-visible companies; most M&A has no public ASN pair
- PeeringDB org map is crawl-time, not historical truth for past days
- Same-org ASN consolidations and leasing ASNs are suppressed but residual noise remains
- Frozen sparse default: do not raise thresholds from lead-lag nulls

See [MA_SIGNAL.md](MA_SIGNAL.md) and [BACKTEST.md](BACKTEST.md).
