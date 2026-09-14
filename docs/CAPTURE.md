# Capture contract (work sqlite vs local JSONL)

Decision: **capture the daily network-contact trickle, not the RIB hose.** Work sqlite is `{--state-dir}/bgp-analyzer.sqlite` (prod `/var/lib/bgp-analyzer/bgp-analyzer.sqlite`). Logical name `bgp-analyzer`. JSONL under `signals/` is a post-commit review copy. The collector must never watch a published snapshot (this crate does not announce one).

Canonical contract: [capturable-state design principles](https://github.com/alexwoolford/capturable-state/blob/main/docs/design-principles.md) §0 / §7 and [datetime.md](https://github.com/alexwoolford/capturable-state/blob/main/docs/datetime.md). Capture the trickle, not the hose.

Pin: `capturable-state` git tag `v0.1.1` (not a path dep; do not copy `src/*.rs`).

## What is captured

| Table / stream | Capture? | Mode | Why |
|---|---|---|---|
| `network_contact` | **yes** | after | Daily product. Downstream join on domains |
| `signal_runs` | **yes** | after | Domain telemetry: did today’s UTC day finish? |
| `org_map_runs` | **yes** | after | Domain telemetry: did the PeeringDB crawl finish? |
| `orgs` (ASN / org / domain spine) | **yes** | after | Join names/domains without re-crawling. **Not** an M&A event stream |
| `pair_state` | **no** | — | Derived (P8). Hard-prunes old pairs. Persistence counts live on the signal row |
| `schema_migrations` | **no** | — | Local DDL versioning |
| RIB snapshots | **no** | — | Hose. Never attach triggers. Never `--snapshot` to “refresh” them |
| Sparse events / pair-features JSONL | **no** | — | Intermediate |
| `signals/signals-YYYY-MM-DD.jsonl` / `inbox.jsonl` | **no** | — | Local review copy written **after** commit |
| Cyber `alerts.jsonl` | **no** | — | Not the product |
| In-memory RIB / MRT `f64` timestamps | **no** | — | Ingest-boundary only |

`score` is a triage heuristic, not a deal probability ([LEAD_LAG_VERDICT.md](LEAD_LAG_VERDICT.md)). It is stored as an integer fact so downstream consumers do not recompute it.

Do not `collect --snapshot` this database to “refresh” RIB-sized files. Incremental `_outbox` drain of the trickle is the steady state.

## Identity

- Signal: undirected pair `(asn_a, asn_b)` plus fact instant `as_of` (RIB window **end**). `CHECK (asn_a < asn_b)`.
- Same-day rerun **upserts** (`ON CONFLICT DO UPDATE`). Ban `INSERT OR REPLACE`.
- Live rows that vanish on rerun get `deleted_at INTEGER` (soft-delete). Pair-state prune is a hard delete on the **uncaptured** table.
- List fields (`domains_a`, `domains_b`, `event_kinds`, `suppress_flags`, org `asns` / `domains`) are comma-separated TEXT. Unnest downstream with `string_to_array` / `text[]`.
- Absent org names: `NULL`, not `''`.
- Org spine: `org_id` (`pdb:…`). HTTP crawl is always a full `/net` pagination; sqlite commit is change-aware (unchanged rows emit no extra outbox events). First crawl emitting ~N inserts is the real initial join state — not a deal list. See [ORG_MAP.md](ORG_MAP.md).
- Run tables: PK `as_of_date` (`YYYY-MM-DD`). Runs do not retract.
- Downstream join key is **domain**. ASN / org is not 1:1 with a ticker.

## Clocks (P5)

| Layer | Columns | Type | Role |
|---|---|---|---|
| Facts | `as_of`, `prior_as_of`, run `started_at` / `finished_at`, org-map `built_at` | TEXT | `YYYY-MM-DDTHH:MM:SSZ` via `utc_iso` (always `Z`, no fraction) |
| Calendar days | `as_of_date`, filename day | TEXT | `YYYY-MM-DD` |
| Envelope | `_outbox.ts`, `deleted_at` | INTEGER Unix seconds | `CAST(strftime('%s','now') AS INTEGER)`. Ordering is `_outbox.seq` |

Snapshot `as_of` is the BGP window `--end` (e.g. `00:30:00Z`), not wall-clock build time. Org-map `built_at` is crawl wall-clock. In-memory `RouteEntry.timestamp` is `f64` Unix seconds at the ingest boundary only.

## Ops

systemd oneshots write announce + nudge:

- `ReadWritePaths=/var/lib/bgp-analyzer /var/lib/state-capture/announce -/run/state` (announce is required when the collector is present; do not prefix it with `-` — that lets a failed bind stay EROFS)
- `TimeoutStartSec=2h`
- Env: `STATE_CAPTURE_SOCK=/run/state/collect.sock`, `STATE_CAPTURE_ANNOUNCE_DIR=/var/lib/state-capture/announce`
- `install.sh` adds `bgp` to group `state-capture` when that group exists (socket is `0660`)
- `install.sh` enables `bgp-signals.timer` **without** `--now` so a Persistent catch-up cannot race the seed crawl

Collector read access to `/var/lib/bgp-analyzer` is configured on the collector host, not in this crate. Do not watch a published copy.

## Conformance checklist

Automated in `bgp-state` tests (CI).

- [x] `_outbox` exists, matches the canonical DDL, `seq` is `AUTOINCREMENT`
- [x] Every table in the capture set has all three triggers
- [x] Each trigger’s column list matches current `PRAGMA table_info` (assert at `install()`)
- [x] A synthetic insert/update/delete on each captured table produces exactly one outbox row, with the right `op` and a non-empty `key`
- [x] A rolled-back transaction produces zero outbox rows
- [x] No `INSERT OR REPLACE` in the source
- [x] Every captured table satisfies P1
- [x] Fact timestamps are TEXT `YYYY-MM-DD` / `YYYY-MM-DDTHH:MM:SSZ`; envelope is INTEGER Unix seconds
- [x] Excluded columns really are excluded (no RIB tables)
- [x] Utility registers on startup and pings after commit (`install()` announce + `nudge.send()`)
- [ ] Killing the collector for 60s, then restarting, loses nothing (ops property; correctness is `_outbox` + collector tick)
