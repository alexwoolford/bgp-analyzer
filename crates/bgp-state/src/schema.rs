//! STRICT DDL for the work sqlite. `_outbox` comes from capturable-state.

pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS network_contact (
  asn_a INTEGER NOT NULL,
  asn_b INTEGER NOT NULL,
  as_of TEXT NOT NULL,
  as_of_date TEXT NOT NULL,
  prior_as_of TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  source TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind = 'network_contact'),
  org_a TEXT CHECK (org_a <> ''),
  org_b TEXT CHECK (org_b <> ''),
  domains_a TEXT NOT NULL,
  domains_b TEXT NOT NULL,
  prefixes_moved INTEGER NOT NULL,
  prefix_move_days INTEGER NOT NULL,
  new_adj_days INTEGER NOT NULL,
  upstream_converge_days INTEGER NOT NULL,
  persistence_days INTEGER NOT NULL,
  score INTEGER NOT NULL,
  event_kinds TEXT NOT NULL,
  suppress_flags TEXT NOT NULL,
  deleted_at INTEGER,
  PRIMARY KEY (asn_a, asn_b, as_of),
  CHECK (asn_a < asn_b),
  CHECK (as_of_date = substr(as_of, 1, 10))
) STRICT;

CREATE TABLE IF NOT EXISTS orgs (
  org_id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL CHECK (name <> ''),
  asns TEXT NOT NULL,
  domains TEXT NOT NULL,
  external_id TEXT CHECK (external_id <> ''),
  deleted_at INTEGER
) STRICT;

CREATE TABLE IF NOT EXISTS signal_runs (
  as_of_date TEXT PRIMARY KEY NOT NULL,
  as_of TEXT NOT NULL,
  prior_as_of TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok', 'snapshot_only', 'error')),
  signal_count INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS org_map_runs (
  as_of_date TEXT PRIMARY KEY NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  built_at TEXT NOT NULL,
  org_count INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS pair_state (
  asn_lo INTEGER NOT NULL,
  asn_hi INTEGER NOT NULL,
  org_lo TEXT,
  org_hi TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  prefix_move_days INTEGER NOT NULL,
  prefixes_moved INTEGER NOT NULL,
  new_adj_days INTEGER NOT NULL,
  upstream_converge_days INTEGER NOT NULL,
  score INTEGER NOT NULL,
  PRIMARY KEY (asn_lo, asn_hi),
  CHECK (asn_lo < asn_hi)
) STRICT;
"#;

pub const CAPTURED_TABLES: &[&str] = &["network_contact", "orgs", "signal_runs", "org_map_runs"];
