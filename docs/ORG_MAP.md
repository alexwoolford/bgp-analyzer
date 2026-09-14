# Org map vs the change stream

PeeringDB is **slowly changing reference data** (ASN ↔ org ↔ domain). It is not the product trickle.

The change stream is daily `network_contact`: RouteViews RIB `T−1` vs `T`, sparse-filtered, same-org/leasing cleaned, then attributed from sqlite `orgs`. Capture that trickle; do not capture the RIB hose. See [CAPTURE.md](CAPTURE.md) and [LEAD_LAG_VERDICT.md](LEAD_LAG_VERDICT.md).

## Two jobs

| Job | Cadence | What it is |
|-----|---------|------------|
| RouteViews RIB diff | Daily | Product. The only BGP change stream this service emits. |
| PeeringDB `/net` + `/org` | Weekly (ops default) | Attribution spine. HTTP is a **full** pagination every run. |

Daily jobs never crawl PeeringDB. They load live `orgs` and refuse if `org_map_runs.finished_at` is older than `ORG_MAP_MAX_AGE_DAYS` (default 14).

Weekly full crawl is a **conservative ops choice**, not a product requirement. ASN↔org mappings change slowly; a map that is days to a few weeks old still attributes “who owns this ASN.” Missing a PeeringDB website edit does not create or destroy a prefix move. Fortnightly or monthly full crawl is enough for attribution; the 14-day gate is what actually constrains freshness. Weekly is ~2× that SLA, with slack if Sunday fails.

Do **not** add PeeringDB `?since=` incremental HTTP unless the 2h oneshot is actually hurting (rate limits, install time). Full crawl plus change-aware sqlite commit is the simpler correct design: deletes are visible, there is no cursor/race surface. [commit_org_map](../crates/bgp-state/src/store.rs) already emits `_outbox` only for new, changed, or retracted orgs.

The expensive recurring job is the **daily RIB**, which is correctly not captured. Tightening subjects / `--focus-from-org-map` has more leverage on cost than making PeeringDB incremental. Crawl-time `is_subject` is called with `prefix_count = None` (the sqlite spine stays “non-glue PeeringDB orgs”). Daily focus then applies **this collector’s origin prefix counts** and keeps snapshot prefixes by origin, not by AS_PATH membership.

## What `orgs` is for

Downstream consumers **join** `orgs` for names and domains. They must **not** treat org upserts as M&A events. The first crawl’s ~N inserts are the real initial join state; later weeks should be a tiny outbox. The M&A-shaped hypothesis lives only on the BGP pair trickle — and even there as a weak prior (`score` is triage, not P(deal)).

This service cannot, no matter how often PeeringDB is crawled:

- See M&A with no ASN-visible network change
- Distinguish a deal from ordinary interconnection or traffic engineering
- Attribute historical RIBs with historical org ownership (the API is live; dated JSON is crawl-time)

Production does not need PeeringDB or RIB history. It needs yesterday’s snapshot, today’s snapshot, and a good-enough org map.
