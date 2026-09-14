//! Numbered DDL migrations for the work sqlite.
//!
//! [`super::schema::SCHEMA_SQL`] is `CREATE TABLE IF NOT EXISTS` only. Live databases
//! will not pick up new columns unless they are applied here.

use anyhow::{Context, Result};
use rusqlite::Connection;

use crate::schema::SCHEMA_BASELINE_VERSION;
use crate::time::utc_iso;

/// Forward migrations after the baseline (`version > 1`).
/// Each entry is `(version, sql)`. Versions must be strictly increasing.
const FORWARD: &[(i64, &str)] = &[];

pub fn apply_migrations(conn: &Connection) -> Result<()> {
    let current: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if current == 0 {
        conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            rusqlite::params![SCHEMA_BASELINE_VERSION, utc_iso(chrono::Utc::now())],
        )
        .context("record schema baseline")?;
    }
    let mut applied = current.max(SCHEMA_BASELINE_VERSION);
    for (version, sql) in FORWARD {
        if *version <= applied {
            continue;
        }
        if *version != applied + 1 {
            anyhow::bail!("schema migration gap: have {applied}, next is {version}");
        }
        conn.execute_batch(sql)
            .with_context(|| format!("schema migration {version}"))?;
        conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
            rusqlite::params![version, utc_iso(chrono::Utc::now())],
        )?;
        applied = *version;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::tests::test_db;

    #[test]
    fn open_records_baseline_migration() {
        let (_dir, db) = test_db();
        let v: i64 = db
            .conn()
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(v, SCHEMA_BASELINE_VERSION);
    }
}
