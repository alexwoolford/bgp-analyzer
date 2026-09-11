# BGP Analyzer

**BGP network-contact signals** for M&A diligence: who touched whose network on the public internet.

Each day the tool diffs consecutive RouteViews RIB snapshots, attributes ASNs to organizations via PeeringDB, and emits sparse events—prefix moves, new adjacency, upstream convergence, footprint steps—with **ASN / org / domain** on each row.

Useful as an **independent contact feed**. It is **not** a ranked deal list: offline evaluation found the signal weak alone for M&A prediction, and `score` is a triage heuristic (not a deal probability).

## Quick start

```bash
cargo build -p bgp-analyzer-cli --release
BGP_DAILY_STATE=data/daily-review ./scripts/run-refresh-org-map.sh
./scripts/run-local-review.sh       # two UTC days → review inbox
```

Review: `data/daily-review/signals/inbox.jsonl` (lossy copy). Facts live in `data/daily-review/bgp-analyzer.sqlite`.

Ongoing daily: `./scripts/run-daily-signals.sh` (default state `data/daily`; refresh into that dir first).

## Deploy

```bash
sudo ./deploy/install.sh
```

Installs under `/opt/bgp-analyzer`, state under `/var/lib/bgp-analyzer`, and enables systemd timers (daily signals + weekly org-map refresh). See [docs/DAILY_OPS.md](docs/DAILY_OPS.md).

## Docs

- [docs/MA_SIGNAL.md](docs/MA_SIGNAL.md) — product mechanics
- [docs/DAILY_OPS.md](docs/DAILY_OPS.md) — ops and systemd
- [docs/CAPTURE.md](docs/CAPTURE.md) — capture contract (work sqlite + `_outbox`)
- [docs/BACKTEST.md](docs/BACKTEST.md) — historical RIB windows
- [docs/LEAD_LAG_VERDICT.md](docs/LEAD_LAG_VERDICT.md) — evaluation headline
- [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [LICENSE](LICENSE)

## Workspace

| Crate | Role |
|-------|------|
| `bgp-ingest` | BGPKIT Broker + MRT streaming |
| `bgp-rib` | Mutable `ipnet-trie` RIB + AS_PATH interning |
| `bgp-map` | Glue ASN list + PeeringDB org map builder |
| `bgp-ma` | Snapshot diff → network-contact events |
| `bgp-state` | STRICT sqlite SoR + capturable-state `_outbox` |
| `bgp-rpki` / `bgp-detect` | Optional cyber path |
| `bgp-analyzer-cli` | `bgp-analyzer` binary |

```bash
cargo test --workspace
```

Inputs and run state live under gitignored `data/`.
