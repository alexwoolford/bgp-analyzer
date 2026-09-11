//! Work sqlite: captured trickle + uncaptured pair_state.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use bgp_ma::{PairStateEntry, PairStateStore, SignalEnvelope};
use bgp_map::{OrgMap, OrgRecord};
use capturable_state::{
    apply_runtime_pragmas, install, CaptureConfig, CaptureMode, Nudge, TableSpec,
};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use tracing::info;

use crate::schema::SCHEMA_SQL;
use crate::time::{parse_utc_iso, utc_date, utc_iso};

/// Collector `src_db` / announce `db_name`.
pub const DB_NAME: &str = "bgp-analyzer";
/// Filename under `--state-dir`.
pub const SQLITE_FILENAME: &str = "bgp-analyzer.sqlite";

pub fn work_db_path(state_dir: impl AsRef<Path>) -> PathBuf {
    state_dir.as_ref().join(SQLITE_FILENAME)
}

fn capture_tables() -> [TableSpec<'static>; 4] {
    [
        TableSpec::new("network_contact", CaptureMode::After),
        TableSpec::new("orgs", CaptureMode::After),
        TableSpec::new("signal_runs", CaptureMode::After),
        TableSpec::new("org_map_runs", CaptureMode::After),
    ]
}

fn is_memory_path(path: &Path) -> bool {
    path == Path::new(":memory:")
}

/// Status for `signal_runs.status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalRunStatus {
    Ok,
    SnapshotOnly,
    Error,
}

impl SignalRunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::SnapshotOnly => "snapshot_only",
            Self::Error => "error",
        }
    }
}

/// One daily (or snapshot-only) signal job.
#[derive(Debug, Clone)]
pub struct SignalRun {
    pub as_of_date: String,
    pub as_of: DateTime<Utc>,
    pub prior_as_of: Option<DateTime<Utc>>,
    pub started_at: DateTime<Utc>,
    pub status: SignalRunStatus,
    pub signal_count: i64,
}

/// Result of committing a PeeringDB crawl.
#[derive(Debug, Clone)]
pub struct OrgMapCommit {
    pub as_of_date: String,
    pub built_at: String,
    pub org_count: i64,
}

pub struct WorkDb {
    conn: Connection,
    nudge: Nudge,
}

impl WorkDb {
    /// Open (or create) the work sqlite and install capture triggers.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(path.as_ref(), None, None)
    }

    pub fn open_with(
        path: &Path,
        announce_dir: Option<&Path>,
        sock: Option<&Path>,
    ) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !is_memory_path(path) {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        apply_runtime_pragmas(&conn)?;
        conn.execute_batch(SCHEMA_SQL)
            .context("create work tables")?;
        let tables = capture_tables();
        let nudge = if is_memory_path(path) {
            Nudge::new(DB_NAME, Some(Path::new("/dev/null")))
        } else {
            let mut cfg = CaptureConfig::new(DB_NAME, path, &tables);
            cfg.announce_dir = announce_dir;
            cfg.sock = sock;
            install(&conn, &cfg).context("capturable-state install")?
        };
        Ok(Self { conn, nudge })
    }

    pub fn require_fresh_org_map(&self, now: DateTime<Utc>, max_age_days: i64) -> Result<OrgMap> {
        let finished = self.latest_org_map_finished_at()?.ok_or_else(|| {
            anyhow::anyhow!("no org_map_runs in work sqlite — run build-org-map first")
        })?;
        let age_days = (now - finished).num_seconds() as f64 / 86_400.0;
        if age_days > max_age_days as f64 {
            bail!(
                "org map too old ({age_days:.1}d > {max_age_days}d); refresh with run-refresh-org-map.sh"
            );
        }
        info!(age_days, max_age_days, "org-map age ok");
        let map = self.load_live_org_map()?;
        if map.is_empty() {
            bail!("no live orgs in work sqlite — run build-org-map first");
        }
        Ok(map)
    }

    pub fn latest_org_map_finished_at(&self) -> Result<Option<DateTime<Utc>>> {
        let s: Option<String> = self
            .conn
            .query_row(
                "SELECT finished_at FROM org_map_runs ORDER BY finished_at DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()
            .context("org_map_runs finished_at")?;
        match s {
            None => Ok(None),
            Some(raw) => Ok(Some(parse_utc_iso(&raw)?)),
        }
    }

    pub fn load_live_org_map(&self) -> Result<OrgMap> {
        let mut stmt = self.conn.prepare(
            "SELECT org_id, name, asns, domains, external_id
             FROM orgs WHERE deleted_at IS NULL",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(OrgRow {
                org_id: r.get(0)?,
                name: r.get(1)?,
                asns: r.get(2)?,
                domains: r.get(3)?,
                external_id: r.get(4)?,
            })
        })?;
        let mut map = OrgMap::new();
        for row in rows {
            let row = row?;
            map.insert(OrgRecord {
                org_id: row.org_id,
                name: row.name,
                asns: split_asns(&row.asns)?,
                domains: split_csv(&row.domains),
                prefix_count_hint: None,
                external_id: row.external_id,
            });
        }
        info!(orgs = map.len(), "loaded org map from sqlite");
        Ok(map)
    }

    pub fn load_pair_state(&self) -> Result<PairStateStore> {
        let mut stmt = self.conn.prepare(
            "SELECT asn_lo, asn_hi, org_lo, org_hi, first_seen, last_seen,
                    prefix_move_days, prefixes_moved, new_adj_days,
                    upstream_converge_days, score
             FROM pair_state",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(PairRow {
                asn_lo: r.get::<_, i64>(0)? as u32,
                asn_hi: r.get::<_, i64>(1)? as u32,
                org_lo: r.get(2)?,
                org_hi: r.get(3)?,
                first_seen: r.get(4)?,
                last_seen: r.get(5)?,
                prefix_move_days: r.get::<_, i64>(6)? as u32,
                prefixes_moved: r.get::<_, i64>(7)? as u32,
                new_adj_days: r.get::<_, i64>(8)? as u32,
                upstream_converge_days: r.get::<_, i64>(9)? as u32,
                score: r.get(10)?,
            })
        })?;
        let mut store = PairStateStore::default();
        for row in rows {
            let row = row?;
            let key = format!("{}-{}", row.asn_lo, row.asn_hi);
            store.pairs.insert(
                key,
                PairStateEntry {
                    asn_lo: row.asn_lo,
                    asn_hi: row.asn_hi,
                    org_lo: row.org_lo,
                    org_hi: row.org_hi,
                    first_seen: parse_utc_iso(&row.first_seen)?,
                    last_seen: parse_utc_iso(&row.last_seen)?,
                    prefix_move_days: row.prefix_move_days,
                    prefixes_moved: row.prefixes_moved,
                    new_adj_days: row.new_adj_days,
                    upstream_converge_days: row.upstream_converge_days,
                    score: row.score,
                },
            );
        }
        Ok(store)
    }

    /// Upsert org spine + `org_map_runs` in one transaction, then nudge.
    pub fn commit_org_map(
        &mut self,
        map: &OrgMap,
        started_at: DateTime<Utc>,
    ) -> Result<OrgMapCommit> {
        if map.is_empty() {
            bail!("refusing to commit empty org map");
        }
        let finished_at = Utc::now();
        let built_at = utc_iso(finished_at);
        let as_of_date = utc_date(started_at);
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            "DROP TABLE IF EXISTS temp.crawl_orgs;
             CREATE TEMP TABLE crawl_orgs (
               org_id TEXT PRIMARY KEY NOT NULL,
               name TEXT NOT NULL,
               asns TEXT NOT NULL,
               domains TEXT NOT NULL,
               external_id TEXT
             ) STRICT;",
        )?;
        {
            let mut ins = tx.prepare(
                "INSERT INTO crawl_orgs(org_id, name, asns, domains, external_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for org in map.orgs() {
                ins.execute(params![
                    org.org_id,
                    org.name,
                    join_asns(&org.asns),
                    join_csv(&org.domains),
                    empty_to_null(org.external_id.as_deref()),
                ])?;
            }
        }
        tx.execute(
            "INSERT INTO orgs(org_id, name, asns, domains, external_id, deleted_at)
             SELECT org_id, name, asns, domains, external_id, NULL FROM crawl_orgs
             WHERE true
             ON CONFLICT(org_id) DO UPDATE SET
               name = excluded.name,
               asns = excluded.asns,
               domains = excluded.domains,
               external_id = excluded.external_id,
               deleted_at = NULL
             WHERE orgs.name IS NOT excluded.name
                OR orgs.asns IS NOT excluded.asns
                OR orgs.domains IS NOT excluded.domains
                OR orgs.external_id IS NOT excluded.external_id
                OR orgs.deleted_at IS NOT NULL",
            [],
        )?;
        tx.execute(
            "UPDATE orgs
             SET deleted_at = CAST(strftime('%s','now') AS INTEGER)
             WHERE deleted_at IS NULL
               AND org_id NOT IN (SELECT org_id FROM crawl_orgs)",
            [],
        )?;
        let org_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM orgs WHERE deleted_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO org_map_runs(as_of_date, started_at, finished_at, built_at, org_count)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(as_of_date) DO UPDATE SET
               started_at = excluded.started_at,
               finished_at = excluded.finished_at,
               built_at = excluded.built_at,
               org_count = excluded.org_count",
            params![
                as_of_date,
                utc_iso(started_at),
                utc_iso(finished_at),
                built_at,
                org_count,
            ],
        )?;
        tx.execute_batch("DROP TABLE IF EXISTS temp.crawl_orgs;")?;
        tx.commit()?;
        self.nudge.send();
        info!(org_count, %as_of_date, "committed org map");
        Ok(OrgMapCommit {
            as_of_date,
            built_at,
            org_count,
        })
    }

    pub fn commit_signal_run(&mut self, run: &SignalRun) -> Result<()> {
        let tx = self.conn.transaction()?;
        upsert_signal_run(&tx, run)?;
        tx.commit()?;
        self.nudge.send();
        Ok(())
    }

    /// Upsert today's signals, retract missing live pairs, replace pair_state, write run.
    pub fn commit_daily(
        &mut self,
        signals: &[SignalEnvelope],
        pair_state: &PairStateStore,
        run: &SignalRun,
    ) -> Result<()> {
        let as_of = utc_iso(run.as_of);
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            "DROP TABLE IF EXISTS temp.keep_pairs;
             CREATE TEMP TABLE keep_pairs (
               asn_a INTEGER NOT NULL,
               asn_b INTEGER NOT NULL,
               PRIMARY KEY (asn_a, asn_b)
             ) STRICT;",
        )?;
        {
            let mut keep = tx.prepare("INSERT INTO keep_pairs(asn_a, asn_b) VALUES (?1, ?2)")?;
            let mut ins = tx.prepare(
                "INSERT INTO network_contact (
                    asn_a, asn_b, as_of, as_of_date, prior_as_of,
                    schema_version, source, kind, org_a, org_b,
                    domains_a, domains_b, prefixes_moved, prefix_move_days,
                    new_adj_days, upstream_converge_days, persistence_days,
                    score, event_kinds, suppress_flags, deleted_at
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5,
                    ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14,
                    ?15, ?16, ?17,
                    ?18, ?19, ?20, NULL
                 )
                 ON CONFLICT(asn_a, asn_b, as_of) DO UPDATE SET
                    as_of_date = excluded.as_of_date,
                    prior_as_of = excluded.prior_as_of,
                    schema_version = excluded.schema_version,
                    source = excluded.source,
                    kind = excluded.kind,
                    org_a = excluded.org_a,
                    org_b = excluded.org_b,
                    domains_a = excluded.domains_a,
                    domains_b = excluded.domains_b,
                    prefixes_moved = excluded.prefixes_moved,
                    prefix_move_days = excluded.prefix_move_days,
                    new_adj_days = excluded.new_adj_days,
                    upstream_converge_days = excluded.upstream_converge_days,
                    persistence_days = excluded.persistence_days,
                    score = excluded.score,
                    event_kinds = excluded.event_kinds,
                    suppress_flags = excluded.suppress_flags,
                    deleted_at = NULL
                 WHERE network_contact.as_of_date IS NOT excluded.as_of_date
                    OR network_contact.prior_as_of IS NOT excluded.prior_as_of
                    OR network_contact.schema_version IS NOT excluded.schema_version
                    OR network_contact.source IS NOT excluded.source
                    OR network_contact.kind IS NOT excluded.kind
                    OR network_contact.org_a IS NOT excluded.org_a
                    OR network_contact.org_b IS NOT excluded.org_b
                    OR network_contact.domains_a IS NOT excluded.domains_a
                    OR network_contact.domains_b IS NOT excluded.domains_b
                    OR network_contact.prefixes_moved IS NOT excluded.prefixes_moved
                    OR network_contact.prefix_move_days IS NOT excluded.prefix_move_days
                    OR network_contact.new_adj_days IS NOT excluded.new_adj_days
                    OR network_contact.upstream_converge_days IS NOT excluded.upstream_converge_days
                    OR network_contact.persistence_days IS NOT excluded.persistence_days
                    OR network_contact.score IS NOT excluded.score
                    OR network_contact.event_kinds IS NOT excluded.event_kinds
                    OR network_contact.suppress_flags IS NOT excluded.suppress_flags
                    OR network_contact.deleted_at IS NOT NULL",
            )?;
            for s in signals {
                ins.execute(params![
                    s.asn_a as i64,
                    s.asn_b as i64,
                    utc_iso(s.as_of),
                    utc_date(s.as_of),
                    utc_iso(s.prior_as_of),
                    s.schema_version as i64,
                    s.source,
                    s.kind,
                    empty_to_null(s.org_a.as_deref()),
                    empty_to_null(s.org_b.as_deref()),
                    join_csv(&s.domains_a),
                    join_csv(&s.domains_b),
                    s.prefixes_moved as i64,
                    s.prefix_move_days as i64,
                    s.new_adj_days as i64,
                    s.upstream_converge_days as i64,
                    s.persistence_days,
                    s.score,
                    join_csv(&s.event_kinds),
                    join_csv(&s.suppress_flags),
                ])?;
                keep.execute(params![s.asn_a as i64, s.asn_b as i64])?;
            }
        }
        tx.execute(
            "UPDATE network_contact
             SET deleted_at = CAST(strftime('%s','now') AS INTEGER)
             WHERE as_of = ?1
               AND deleted_at IS NULL
               AND (asn_a, asn_b) NOT IN (SELECT asn_a, asn_b FROM keep_pairs)",
            params![as_of],
        )?;
        replace_pair_state(&tx, pair_state)?;
        upsert_signal_run(&tx, run)?;
        tx.execute_batch("DROP TABLE IF EXISTS temp.keep_pairs;")?;
        tx.commit()?;
        self.nudge.send();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    #[cfg(test)]
    pub(crate) fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

struct OrgRow {
    org_id: String,
    name: String,
    asns: String,
    domains: String,
    external_id: Option<String>,
}

struct PairRow {
    asn_lo: u32,
    asn_hi: u32,
    org_lo: Option<String>,
    org_hi: Option<String>,
    first_seen: String,
    last_seen: String,
    prefix_move_days: u32,
    prefixes_moved: u32,
    new_adj_days: u32,
    upstream_converge_days: u32,
    score: i64,
}

fn upsert_signal_run(tx: &Transaction<'_>, run: &SignalRun) -> Result<()> {
    let finished_at = utc_iso(Utc::now());
    tx.execute(
        "INSERT INTO signal_runs(
            as_of_date, as_of, prior_as_of, started_at, finished_at, status, signal_count
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(as_of_date) DO UPDATE SET
            as_of = excluded.as_of,
            prior_as_of = excluded.prior_as_of,
            started_at = excluded.started_at,
            finished_at = excluded.finished_at,
            status = excluded.status,
            signal_count = excluded.signal_count",
        params![
            run.as_of_date,
            utc_iso(run.as_of),
            run.prior_as_of.map(utc_iso),
            utc_iso(run.started_at),
            finished_at,
            run.status.as_str(),
            run.signal_count,
        ],
    )?;
    Ok(())
}

fn replace_pair_state(tx: &Transaction<'_>, store: &PairStateStore) -> Result<()> {
    tx.execute("DELETE FROM pair_state", [])?;
    let mut ins = tx.prepare(
        "INSERT INTO pair_state(
            asn_lo, asn_hi, org_lo, org_hi, first_seen, last_seen,
            prefix_move_days, prefixes_moved, new_adj_days,
            upstream_converge_days, score
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )?;
    for e in store.pairs.values() {
        ins.execute(params![
            e.asn_lo as i64,
            e.asn_hi as i64,
            empty_to_null(e.org_lo.as_deref()),
            empty_to_null(e.org_hi.as_deref()),
            utc_iso(e.first_seen),
            utc_iso(e.last_seen),
            e.prefix_move_days as i64,
            e.prefixes_moved as i64,
            e.new_adj_days as i64,
            e.upstream_converge_days as i64,
            e.score,
        ])?;
    }
    Ok(())
}

pub fn join_csv(parts: &[String]) -> String {
    parts.join(",")
}

pub fn join_asns(asns: &[u32]) -> String {
    asns.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn split_csv(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split(',').map(|x| x.to_string()).collect()
    }
}

fn split_asns(s: &str) -> Result<Vec<u32>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    s.split(',')
        .map(|p| {
            p.parse::<u32>()
                .with_context(|| format!("invalid ASN in captured asns {s:?}"))
        })
        .collect()
}

fn empty_to_null(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|x| !x.is_empty())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::schema::CAPTURED_TABLES;
    use chrono::TimeZone;
    use tempfile::TempDir;

    pub(crate) fn test_db() -> (TempDir, WorkDb) {
        let dir = TempDir::new().unwrap();
        let sqlite = dir.path().join("bgp-analyzer.sqlite");
        let announce = dir.path().join("announce");
        std::fs::create_dir(&announce).unwrap();
        let db = WorkDb::open_with(&sqlite, Some(&announce), Some(Path::new("/dev/null"))).unwrap();
        (dir, db)
    }

    fn sample_org(id: &str, asn: u32) -> OrgRecord {
        OrgRecord {
            org_id: id.into(),
            name: format!("org-{id}"),
            asns: vec![asn],
            domains: vec![format!("{id}.example")],
            prefix_count_hint: None,
            external_id: Some(format!("ext-{id}")),
        }
    }

    fn sample_signal(score: i64) -> SignalEnvelope {
        SignalEnvelope {
            schema_version: 1,
            source: "bgp_analyzer".into(),
            kind: "network_contact".into(),
            as_of: Utc.with_ymd_and_hms(2026, 8, 14, 0, 30, 0).unwrap(),
            prior_as_of: Utc.with_ymd_and_hms(2026, 8, 13, 0, 30, 0).unwrap(),
            asn_a: 1,
            asn_b: 2,
            org_a: Some("pdb:1".into()),
            org_b: Some("pdb:2".into()),
            domains_a: vec!["a.example".into()],
            domains_b: vec!["b.example".into()],
            prefixes_moved: 3,
            prefix_move_days: 1,
            new_adj_days: 0,
            upstream_converge_days: 0,
            persistence_days: 0,
            score,
            event_kinds: vec!["prefix_move".into()],
            suppress_flags: vec![],
        }
    }

    fn run_ok(n: i64) -> SignalRun {
        SignalRun {
            as_of_date: "2026-08-14".into(),
            as_of: Utc.with_ymd_and_hms(2026, 8, 14, 0, 30, 0).unwrap(),
            prior_as_of: Some(Utc.with_ymd_and_hms(2026, 8, 13, 0, 30, 0).unwrap()),
            started_at: Utc.with_ymd_and_hms(2026, 8, 14, 2, 30, 0).unwrap(),
            status: SignalRunStatus::Ok,
            signal_count: n,
        }
    }

    pub(crate) fn outbox_ops(conn: &Connection, tbl: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT op FROM _outbox WHERE tbl = ?1 ORDER BY seq")
            .unwrap();
        stmt.query_map([tbl], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn announce_file_written() {
        let (dir, _db) = test_db();
        let body =
            std::fs::read_to_string(dir.path().join("announce").join("bgp-analyzer.json")).unwrap();
        assert!(body.contains("bgp-analyzer"));
        assert!(body.contains("bgp-analyzer.sqlite"));
    }

    #[test]
    fn unchanged_org_upsert_no_extra_outbox() {
        let (_dir, mut db) = test_db();
        let mut map = OrgMap::new();
        map.insert(sample_org("pdb:1", 1));
        let t0 = Utc.with_ymd_and_hms(2026, 9, 1, 12, 0, 0).unwrap();
        db.commit_org_map(&map, t0).unwrap();
        let n1: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM _outbox WHERE tbl = 'orgs'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n1, 1);
        db.commit_org_map(&map, t0).unwrap();
        let n2: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM _outbox WHERE tbl = 'orgs'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n2, 1, "unchanged crawl must not emit extra org events");
    }

    #[test]
    fn org_retract_soft_deletes() {
        let (_dir, mut db) = test_db();
        let mut map = OrgMap::new();
        map.insert(sample_org("pdb:1", 1));
        map.insert(sample_org("pdb:2", 2));
        let t0 = Utc.with_ymd_and_hms(2026, 9, 1, 12, 0, 0).unwrap();
        db.commit_org_map(&map, t0).unwrap();
        let mut next = OrgMap::new();
        next.insert(sample_org("pdb:1", 1));
        db.commit_org_map(&next, t0).unwrap();
        let deleted: Option<i64> = db
            .conn()
            .query_row(
                "SELECT deleted_at FROM orgs WHERE org_id = 'pdb:2'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(deleted.is_some());
        let live = db.load_live_org_map().unwrap();
        assert_eq!(live.len(), 1);
        assert!(live.get("pdb:2").is_none());
    }

    #[test]
    fn same_day_signal_rerun_is_update() {
        let (_dir, mut db) = test_db();
        db.commit_daily(&[sample_signal(5)], &PairStateStore::default(), &run_ok(1))
            .unwrap();
        assert_eq!(outbox_ops(db.conn(), "network_contact"), vec!["I"]);
        db.commit_daily(&[sample_signal(9)], &PairStateStore::default(), &run_ok(1))
            .unwrap();
        assert_eq!(outbox_ops(db.conn(), "network_contact"), vec!["I", "U"]);
        let score: i64 = db
            .conn()
            .query_row("SELECT score FROM network_contact", [], |r| r.get(0))
            .unwrap();
        assert_eq!(score, 9);
    }

    #[test]
    fn identical_same_day_rerun_no_extra_outbox() {
        let (_dir, mut db) = test_db();
        db.commit_daily(&[sample_signal(5)], &PairStateStore::default(), &run_ok(1))
            .unwrap();
        assert_eq!(outbox_ops(db.conn(), "network_contact"), vec!["I"]);
        db.commit_daily(&[sample_signal(5)], &PairStateStore::default(), &run_ok(1))
            .unwrap();
        assert_eq!(
            outbox_ops(db.conn(), "network_contact"),
            vec!["I"],
            "identical rerun must not emit a spurious U"
        );
    }

    #[test]
    fn signal_run_error_status_round_trips() {
        let (_dir, mut db) = test_db();
        db.commit_signal_run(&SignalRun {
            as_of_date: "2026-08-14".into(),
            as_of: Utc.with_ymd_and_hms(2026, 8, 14, 0, 30, 0).unwrap(),
            prior_as_of: None,
            started_at: Utc.with_ymd_and_hms(2026, 8, 14, 2, 30, 0).unwrap(),
            status: SignalRunStatus::Error,
            signal_count: 0,
        })
        .unwrap();
        let status: String = db
            .conn()
            .query_row(
                "SELECT status FROM signal_runs WHERE as_of_date = '2026-08-14'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "error");
    }

    #[test]
    fn signal_retract_sets_deleted_at() {
        let (_dir, mut db) = test_db();
        db.commit_daily(&[sample_signal(5)], &PairStateStore::default(), &run_ok(1))
            .unwrap();
        db.commit_daily(&[], &PairStateStore::default(), &run_ok(0))
            .unwrap();
        let deleted: Option<i64> = db
            .conn()
            .query_row("SELECT deleted_at FROM network_contact", [], |r| r.get(0))
            .unwrap();
        assert!(deleted.is_some());
        assert_eq!(outbox_ops(db.conn(), "network_contact"), vec!["I", "U"]);
    }

    #[test]
    fn pair_state_does_not_emit_outbox() {
        let (_dir, mut db) = test_db();
        let mut st = PairStateStore::default();
        let ts = Utc.with_ymd_and_hms(2026, 8, 14, 0, 30, 0).unwrap();
        st.pairs.insert(
            "1-2".into(),
            PairStateEntry {
                asn_lo: 1,
                asn_hi: 2,
                org_lo: Some("a".into()),
                org_hi: Some("b".into()),
                first_seen: ts,
                last_seen: ts,
                prefix_move_days: 1,
                prefixes_moved: 2,
                new_adj_days: 0,
                upstream_converge_days: 0,
                score: 3,
            },
        );
        db.commit_daily(&[], &st, &run_ok(0)).unwrap();
        let n: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM _outbox WHERE tbl = 'pair_state'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
        let loaded = db.load_pair_state().unwrap();
        assert!(loaded.get(1, 2).is_some());
    }

    #[test]
    fn captured_tables_listed() {
        assert_eq!(
            CAPTURED_TABLES,
            &["network_contact", "orgs", "signal_runs", "org_map_runs"]
        );
    }
}
