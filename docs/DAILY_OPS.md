# BGP daily network-contact signals (ops)

## Product

This repo emits **BGP network-contact signals**: attributable contact between non-glue organizations’ networks. The daily default is **`prefix_move` with ≥2 prefixes** on the same ASN pair. New adjacency, upstream convergence, and footprint steps are diff/`--full`/backtest only — not the production sqlite emit.

`score` is a **triage heuristic**, not a calibrated deal probability. Offline lead-lag work found low precision when treating high scores as M&A leads — do not rank “BGP first” for deal discovery. See [LEAD_LAG_VERDICT.md](LEAD_LAG_VERDICT.md).

## Diff mechanics

Quiet production is a **rolling day pair**:

1. Fetch (or reuse) today’s RouteViews RIB → origin-collapsed snapshot
2. Diff vs the prior retained snapshot (`T−1` vs `T`)
3. Sparse-filter (`prefix_move` with ≥2 prefixes per ASN pair by default)
4. Drop glue (either side), leasing, unattributed (missing org id), same PeeringDB org, and same-family (shared registrable domain) pairs
5. Update 30-day rolling pair state (persistence)
6. Emit versioned signals (`kind=network_contact`)

Long historical backtests (monthly RIBs) are for **evaluation**, not the hot path. Local quarantine and downloads stay under gitignored `data/` — never in the product tree.

## Org map (PeeringDB reference data)

The ASN↔org↔domain map is **slowly changing reference data** for attribution, not the change stream. The product trickle is daily `network_contact` (RIB `T−1` vs `T`). See [ORG_MAP.md](ORG_MAP.md).

PeeringDB HTTP is a **full** `/net` pagination every refresh (polite, not free). Sqlite/`_outbox` commit is change-aware: unchanged orgs emit no extra events. Weekly Sunday crawl is a conservative ops default (~2× the 14-day age gate), not a product requirement. Cadence knobs: `bgp-org-map.timer` and `ORG_MAP_MAX_AGE_DAYS`. Do not add incremental PeeringDB `?since=` unless the 2h oneshot is actually hurting.

Anonymous PeeringDB cap is **20 req/min** (≥3.1s between queries in `bgp-map`). 429 / 5xx retry up to 12 times (`Retry-After` or exponential backoff). Declared UA: `bgp-analyzer/0.1 (research; real-data org-map builder)`. Do not raise the crawl rate to beat `TimeoutStartSec=2h`.

| Cadence | Job | Behavior |
|---------|-----|----------|
| **Weekly** | `./scripts/run-refresh-org-map.sh` | Full PeeringDB crawl → work sqlite `orgs` / `org_map_runs`; dated JSON + `current` symlink is a local copy |
| **Daily** | `./scripts/run-daily-signals.sh` | Load live orgs from sqlite; **refuse** if `org_map_runs.finished_at` is older than `ORG_MAP_MAX_AGE_DAYS` (default 14) |

Daily does **not** crawl PeeringDB. Overlay (`BGP_ORG_MAP_OVERLAY`) is opt-in for local eval — do not set it in production. Downstream must join `orgs` for names/domains and must not treat org upserts as M&A events.

## Local review (eyeball a run)

Do **not** look at cyber `alerts.jsonl`. Product output is the daily signal inbox.

```bash
cargo build -p bgp-analyzer-cli --release

# Org map once into the review state dir (sqlite SoR)
BGP_DAILY_STATE=data/daily-review ./scripts/run-refresh-org-map.sh

# Two consecutive UTC days (needs network for RouteViews RIBs)
./scripts/run-local-review.sh
# or pin dates:
./scripts/run-local-review.sh 2024-06-01 2024-06-02
```

Review:

- `data/daily-review/bgp-analyzer.sqlite` — system of record (`network_contact`)
- `data/daily-review/signals/signals-YYYY-MM-DD.jsonl` — that day’s review copy (after commit)
- `data/daily-review/signals/inbox.jsonl` — append-only; **not** idempotent on same-day rerun

Day 1 only stores a snapshot; day 2 diffs and writes signals. Expect real RIB downloads (minutes).

## Local run (ongoing)

```bash
cargo build -p bgp-analyzer-cli --release

./scripts/run-refresh-org-map.sh   # once (or weekly)
./scripts/run-daily-signals.sh     # first day stores snapshot only
./scripts/run-daily-signals.sh     # next UTC day emits signals
```

Env overrides: `BGP_ANALYZER_BIN`, `BGP_DAILY_STATE`, `BGP_ORG_MAP_DIR` (dated JSON copy from refresh), `BGP_GLUE`, `BGP_ORG_MAP_OVERLAY` (opt-in), `BGP_COLLECTOR`, `ORG_MAP_MAX_AGE_DAYS`. Daily loads orgs from sqlite, not `BGP_ORG_MAP`.

Default enables `--focus-from-org-map`: subject ASNs after applying **RIB origin prefix counts** to `SubjectHeuristics`, then keep prefixes whose **origin** is in that set. Pass `--debug-jsonl` to write intermediate `events/` files.

## Deploy (systemd, recommended)

### Deploy decision

**Prefer git clone (or a tagged checkout) + [`deploy/install.sh`](../deploy/install.sh) + systemd timers.** Do not ship a dnf/RPM package for the first production hosts.

This is a lightweight batch emitter (daily RIB diff, weekly PeeringDB crawl), not a multi-host daemon fleet. Clone → build release → install under `/opt` with state in `/var/lib` is enough. A dnf package (private repo, signing, buildroot) can wait until you need many identical hosts or hosts without a Rust toolchain; then ship a **prebuilt** binary RPM that installs the same layout.

Do **not** run production from a developer checkout under `$HOME` with ad-hoc cron. Use the `/opt` + `/var/lib` split below.

Oneshot + timer. The OS is the scheduler. Operator logs: `tracing` on stderr → journald (`SyslogIdentifier=bgp-signals` / `bgp-org-map`). Default `RUST_LOG=info`.

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
| `bgp-org-map.timer` | Sunday 01:00 UTC + 15m jitter, `Persistent=true` |
| `bgp-signals.timer` | Daily 02:30 UTC + 15m jitter, `Persistent=true` |

Config: `/opt/bgp-analyzer/etc/bgp-analyzer.env` (from [`deploy/bgp-analyzer.env.example`](../deploy/bgp-analyzer.env.example), **chmod 600**). Install does not overwrite an existing env. `TimeoutStartSec=2h` on both oneshots.

Install **enables** both timers without `--now` so `Persistent=true` cannot catch up and race the seed crawl. The seed org-map oneshot is started explicitly. Timers become active on the next boot; if this host will not reboot soon, start them after `org_map_runs` exists:

```bash
sudo systemctl start bgp-org-map.timer bgp-signals.timer
```

Starting `bgp-signals.timer` may immediately run today’s daily job (`Persistent=true`). That is safe once the org map is seeded (`run-daily-signals.sh` exits 0 if it is not).

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
/var/lib/bgp-analyzer/
  bgp-analyzer.sqlite            # work sqlite (signals, orgs, runs, _outbox)
  snapshots/  events/  signals/  # RIB hose + JSONL review copies
/var/lib/bgp-analyzer/org-map/
  org-map-peeringdb-YYYY-MM-DD.json
  current -> …
```

Upgrades: `git pull` (or new tag) → re-run `sudo ./deploy/install.sh` (env file at `/opt/bgp-analyzer/etc/bgp-analyzer.env` is preserved if already present).

### Collecting signals (after install)

```bash
# Work sqlite (system of record)
sudo -u bgp sqlite3 /var/lib/bgp-analyzer/bgp-analyzer.sqlite \
  "SELECT COUNT(*) FROM network_contact WHERE deleted_at IS NULL;"

# Append-only review feed (lossy; same-day reruns duplicate lines)
sudo -u bgp less /var/lib/bgp-analyzer/signals/inbox.jsonl

# One UTC calendar day
sudo -u bgp less /var/lib/bgp-analyzer/signals/signals-YYYY-MM-DD.jsonl
```

Each record includes UTC observation times `as_of` (later RIB day) and `prior_as_of` (prior snapshot). Dated files use `signals-YYYY-MM-DD.jsonl`. Job wall-clock: `journalctl -u bgp-signals.service`.

### Verify install

```bash
systemctl list-timers 'bgp-*'
journalctl -u bgp-signals.service -u bgp-org-map.service -n 50 --no-pager
du -sh /var/lib/bgp-analyzer   # origin-focused snapshots; pruned via --retain-days
```

Manual oneshots:

```bash
sudo systemctl start bgp-org-map.service    # PeeringDB refresh (also on weekly timer)
sudo systemctl start bgp-signals.service    # today’s UTC day
# or pin a calendar day:
sudo -u bgp bash -lc 'set -a; source /opt/bgp-analyzer/etc/bgp-analyzer.env; set +a; /opt/bgp-analyzer/scripts/run-daily-signals.sh 2024-06-02'
```

First day after install only stores a snapshot; the next UTC day (or a second pinned date) emits signals.

## Timer failed

`Persistent=true` will retry after a reboot. It will not page you. Do not hand-edit sqlite.

1. `systemctl list-failed --no-pager` and `systemctl list-timers 'bgp-*'`.
2. `journalctl -u bgp-signals.service -u bgp-org-map.service -n 80 --no-pager`.
3. Query run tables (domain telemetry; also captured):

```bash
sudo -u bgp sqlite3 /var/lib/bgp-analyzer/bgp-analyzer.sqlite \
  "SELECT as_of_date, status, signal_count, started_at, finished_at
   FROM signal_runs ORDER BY as_of_date DESC LIMIT 5;"
sudo -u bgp sqlite3 /var/lib/bgp-analyzer/bgp-analyzer.sqlite \
  "SELECT as_of_date, org_count, started_at, finished_at
   FROM org_map_runs ORDER BY as_of_date DESC LIMIT 5;"
```

4. Re-run: `sudo systemctl start bgp-org-map.service` and/or `sudo systemctl start bgp-signals.service`.

Exit classes already in the wrappers and binary:

| What you see | Meaning |
|---|---|
| Daily wrapper logs “org map not seeded yet” and **exit 0** | Missing `bgp-analyzer.sqlite` or empty `org_map_runs`. Wait for the seed crawl; not a unit failure. |
| `signal_runs.status=snapshot_only` and **exit 0** | First UTC day (or no prior RIB file). Success; the next day diffs. |
| `signal_runs.status=error` and unit **failed** | Daily job panicked/bailed after open; row is marked in `inspect_err`. |
| `org map too old (…d > …d)` | `ORG_MAP_MAX_AGE_DAYS` gate (default 14). Start `bgp-org-map.service`. |
| `already running (lock …)` and **exit 1** | `flock` overlap. Let the in-flight oneshot finish; do not start a second copy. |
| PeeringDB `429` / 5xx then give-up after 12 retries | Rate limit or API outage. Unit failed; next timer or a manual start is the retry. |
| Killed at **2h** | `TimeoutStartSec=2h`. Check RouteViews download size / PeeringDB crawl; do not drop the ≥3.1s interval. |

## State capture

Work sqlite: `/var/lib/bgp-analyzer/bgp-analyzer.sqlite` (`db_name` `bgp-analyzer`). `capturable-state` v0.1.1 installs `_outbox` on `network_contact`, `orgs`, `signal_runs`, `org_map_runs`. JSONL under `signals/` is a post-commit review copy.

systemd `ReadWritePaths` includes `/var/lib/state-capture/announce` (required; no `-` prefix) and `-/run/state`. `install.sh` adds `bgp` to group `state-capture` and makes the announce dir group-writable when that group exists. Seed crawl is `systemctl start --no-block bgp-org-map.service` (not a blocking SSH `install.sh` step). Env: `STATE_CAPTURE_SOCK`, `STATE_CAPTURE_ANNOUNCE_DIR`. Collector read access to `/var/lib/bgp-analyzer` is configured on the collector host, not in this crate. Contract: [CAPTURE.md](CAPTURE.md).

## Outputs (reviewable)

Under the state dir (`data/daily/` locally, `/var/lib/bgp-analyzer/` in production — gitignored):

| Path | Purpose |
|------|---------|
| `bgp-analyzer.sqlite` | Work sqlite: signals, orgs, run tables, `_outbox`; uncaptured `pair_state` |
| `snapshots/rib-YYYY-MM-DD.json` | Rolling RIB origin snapshots (hose; not captured) |
| `events/*.jsonl` | Intermediate hose; written only with `--debug-jsonl` |
| `signals/signals-YYYY-MM-DD.jsonl` | Signal envelope (lossy review copy after commit) |
| `signals/inbox.jsonl` | Append-only human review feed (not idempotent) |

### Signal envelope (`schema_version: 1`)

- `source`: `bgp_analyzer`
- `kind`: `network_contact`
- `as_of` / `prior_as_of`
- Attributes: `asn_a`/`asn_b`, `org_a`/`org_b`, `domains_a`/`domains_b`
- `prefixes_moved`, day counts, `persistence_days`, triage `score`

## Limits

- Only ASN-visible companies; most M&A has no public ASN pair
- PeeringDB org map is crawl-time, not historical truth for past days
- Glue, leasing, missing org ids, same PeeringDB org, and shared-domain families are suppressed; PeeringDB org ≠ ultimate parent, so residual intra-group noise can remain
- Frozen sparse default: do not raise thresholds from lead-lag nulls
- Daily RouteViews RIB is the expensive recurring job (not captured). `--focus-from-org-map` applies RIB prefix counts and origin-only retain; first install skips signals until `org_map_runs` exists
- Install enables both **timers** without `--now` so a Persistent catch-up cannot race the seed crawl. Seed is `systemctl start --no-block bgp-org-map.service`. `run-daily-signals.sh` exits 0 if the org map is not seeded yet.

See [MA_SIGNAL.md](MA_SIGNAL.md), [ORG_MAP.md](ORG_MAP.md), and [BACKTEST.md](BACKTEST.md).
