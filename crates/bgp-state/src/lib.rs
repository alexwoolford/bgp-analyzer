//! STRICT sqlite system of record for BGP network-contact signals.
//!
//! Captured: `network_contact`, `orgs`, `signal_runs`, `org_map_runs`.
//! Uncaptured: `pair_state`. RIB snapshots stay files.

mod migrate;
mod schema;
mod store;
mod time;

pub use schema::{CAPTURED_TABLES, SCHEMA_BASELINE_VERSION, SCHEMA_SQL};
pub use store::{
    join_asns, join_csv, work_db_path, OrgMapCommit, SignalRun, SignalRunStatus, WorkDb, DB_NAME,
    SQLITE_FILENAME,
};
pub use time::{parse_utc_iso, utc_date, utc_iso, DATE_FMT, INSTANT_FMT};

#[cfg(test)]
mod conformance {
    use super::*;
    use crate::store::tests::{outbox_ops, test_db};
    use rusqlite::Connection;
    use std::fs;
    use std::path::PathBuf;

    fn outbox_ddl(conn: &Connection) -> String {
        conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = '_outbox'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn trigger_names(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'trigger' AND name GLOB ?1
                 ORDER BY name",
            )
            .unwrap();
        let glob = format!("_cap_*_{table}");
        stmt.query_map([glob], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn outbox_exists_autoincrement_strict() {
        let (_dir, db) = test_db();
        let sql = outbox_ddl(db.conn());
        let u = sql.to_ascii_uppercase();
        assert!(u.contains("AUTOINCREMENT"));
        assert!(u.contains("STRICT"));
    }

    #[test]
    fn every_captured_table_has_three_triggers() {
        let (_dir, db) = test_db();
        for table in CAPTURED_TABLES {
            let names = trigger_names(db.conn(), table);
            assert_eq!(names.len(), 3, "{table} triggers: {names:?}");
            assert!(names.iter().any(|n| n == &format!("_cap_I_{table}")));
            assert!(names.iter().any(|n| n == &format!("_cap_U_{table}")));
            assert!(names.iter().any(|n| n == &format!("_cap_D_{table}")));
        }
    }

    #[test]
    fn synthetic_iud_one_outbox_row_each() {
        let (_dir, mut db) = test_db();
        let conn = db.conn_mut();

        conn.execute(
            "INSERT INTO network_contact(
                asn_a, asn_b, as_of, as_of_date, prior_as_of, schema_version, source, kind,
                domains_a, domains_b, prefixes_moved, prefix_move_days, new_adj_days,
                upstream_converge_days, persistence_days, score, event_kinds, suppress_flags
             ) VALUES (1, 2, '2026-08-14T00:30:00Z', '2026-08-14', '2026-08-13T00:30:00Z',
                       1, 'bgp_analyzer', 'network_contact', '', '', 1, 1, 0, 0, 0, 1, 'prefix_move', '')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE network_contact SET score = 2 WHERE asn_a = 1 AND asn_b = 2",
            [],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM network_contact WHERE asn_a = 1 AND asn_b = 2",
            [],
        )
        .unwrap();
        assert_eq!(outbox_ops(conn, "network_contact"), vec!["I", "U", "D"]);
        let key: String = conn
            .query_row(
                "SELECT key FROM _outbox WHERE tbl = 'network_contact' AND op = 'I'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(key.contains("asn_a"));
        assert!(key.contains("asn_b"));
        assert!(key.contains("as_of"));
        assert!(!key.is_empty());

        conn.execute(
            "INSERT INTO orgs(org_id, name, asns, domains) VALUES ('pdb:1', 'Acme', '1', 'acme.example')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE orgs SET name = 'Acme Inc' WHERE org_id = 'pdb:1'",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM orgs WHERE org_id = 'pdb:1'", [])
            .unwrap();
        assert_eq!(outbox_ops(conn, "orgs"), vec!["I", "U", "D"]);
        let org_key: String = conn
            .query_row(
                "SELECT key FROM _outbox WHERE tbl = 'orgs' AND op = 'I'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(org_key.contains("org_id"));

        conn.execute(
            "INSERT INTO signal_runs(as_of_date, as_of, started_at, finished_at, status, signal_count)
             VALUES ('2026-08-14', '2026-08-14T00:30:00Z', '2026-08-14T02:30:00Z',
                     '2026-08-14T03:00:00Z', 'ok', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE signal_runs SET signal_count = 2 WHERE as_of_date = '2026-08-14'",
            [],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM signal_runs WHERE as_of_date = '2026-08-14'",
            [],
        )
        .unwrap();
        assert_eq!(outbox_ops(conn, "signal_runs"), vec!["I", "U", "D"]);

        conn.execute(
            "INSERT INTO org_map_runs(as_of_date, started_at, finished_at, built_at, org_count)
             VALUES ('2026-08-14', '2026-08-14T00:00:00Z', '2026-08-14T00:10:00Z',
                     '2026-08-14T00:10:00Z', 3)",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE org_map_runs SET org_count = 4 WHERE as_of_date = '2026-08-14'",
            [],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM org_map_runs WHERE as_of_date = '2026-08-14'",
            [],
        )
        .unwrap();
        assert_eq!(outbox_ops(conn, "org_map_runs"), vec!["I", "U", "D"]);
    }

    #[test]
    fn rollback_produces_zero_outbox_rows() {
        let (_dir, mut db) = test_db();
        let before: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM _outbox", [], |r| r.get(0))
            .unwrap();
        {
            let tx = db.conn_mut().transaction().unwrap();
            tx.execute(
                "INSERT INTO orgs(org_id, name, asns, domains)
                 VALUES ('pdb:rollback', 'X', '9', '')",
                [],
            )
            .unwrap();
            tx.rollback().unwrap();
        }
        let after: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM _outbox", [], |r| r.get(0))
            .unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn p1_keys_are_natural() {
        let (_dir, db) = test_db();
        let conn = db.conn();
        for (table, col) in [
            ("network_contact", "asn_a"),
            ("orgs", "org_id"),
            ("signal_runs", "as_of_date"),
            ("org_map_runs", "as_of_date"),
        ] {
            let pk: i64 = conn
                .query_row(
                    "SELECT pk FROM pragma_table_info(?1) WHERE name = ?2",
                    rusqlite::params![table, col],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(pk > 0, "{table}.{col} must be in the primary key");
        }
    }

    #[test]
    fn no_rib_tables() {
        let (_dir, db) = test_db();
        let n: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'
                 AND name IN ('rib', 'snapshots', 'routes', 'as_path')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn no_insert_or_replace_in_rust_source() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut hits = Vec::new();
        let crates = root.join("crates");
        let mut stack = vec![crates];
        while let Some(dir) = stack.pop() {
            for ent in fs::read_dir(&dir).unwrap() {
                let ent = ent.unwrap();
                let path = ent.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                    continue;
                }
                let text = fs::read_to_string(&path).unwrap();
                for (i, line) in text.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("//") {
                        continue;
                    }
                    let banned = format!("INSERT OR {}", "REPLACE");
                    if trimmed.to_ascii_uppercase().contains(&banned) {
                        hits.push(format!("{}:{}", path.display(), i + 1));
                    }
                }
            }
        }
        assert!(
            hits.is_empty(),
            "banned upsert idiom found:\n{}",
            hits.join("\n")
        );
    }
}
