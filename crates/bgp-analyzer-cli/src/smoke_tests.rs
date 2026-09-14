//! Offline smoke tests for CLI helpers and daily signal schema.

use chrono::{Datelike, TimeZone, Utc};

use crate::commands::{parse_ymd, prune_snapshots};

#[test]
fn parse_ymd_accepts_iso_dates() {
    let d = parse_ymd("2026-08-14").unwrap();
    assert_eq!(d.year(), 2026);
    assert_eq!(d.month(), 8);
    assert_eq!(d.day(), 14);
}

#[test]
fn parse_ymd_rejects_garbage() {
    assert!(parse_ymd("not-a-date").is_err());
    assert!(parse_ymd("2026/08/14").is_err());
}

#[test]
fn prune_snapshots_retains_recent_only() {
    let dir = tempfile_dir();
    let as_of = parse_ymd("2026-08-14").unwrap();
    for day in ["2026-08-10", "2026-08-12", "2026-08-14"] {
        std::fs::write(dir.join(format!("rib-{day}.json")), b"{}").unwrap();
    }
    prune_snapshots(&dir, as_of, 2).unwrap();
    assert!(!dir.join("rib-2026-08-10.json").exists());
    assert!(dir.join("rib-2026-08-12.json").exists());
    assert!(dir.join("rib-2026-08-14.json").exists());
}

#[test]
fn daily_signal_json_schema_roundtrip() {
    use bgp_ma::SignalEnvelope;

    let env = SignalEnvelope {
        schema_version: 1,
        source: "bgp_analyzer".into(),
        kind: "network_contact".into(),
        as_of: Utc.with_ymd_and_hms(2026, 8, 14, 0, 30, 0).unwrap(),
        prior_as_of: Utc.with_ymd_and_hms(2026, 8, 13, 0, 30, 0).unwrap(),
        asn_a: 65000,
        asn_b: 65001,
        org_a: Some("org:a".into()),
        org_b: Some("org:b".into()),
        domains_a: vec!["a.example".into()],
        domains_b: vec!["b.example".into()],
        prefixes_moved: 3,
        prefix_move_days: 1,
        new_adj_days: 0,
        upstream_converge_days: 0,
        persistence_days: 1,
        score: 12,
        event_kinds: vec!["prefix_move".into()],
        suppress_flags: vec![],
    };
    let line = serde_json::to_string(&env).unwrap();
    let back: SignalEnvelope = serde_json::from_str(&line).unwrap();
    assert_eq!(back.source, "bgp_analyzer");
    assert_eq!(back.kind, "network_contact");
    assert_eq!(back.schema_version, 1);
    assert!(!line.contains("\"tile\""));
    assert!(!line.contains("corroboration"));
    assert!(line.contains("2026-08-14T00:30:00Z"));
    assert!(!line.contains("+00:00"));
    assert_eq!(back, env);
}

#[test]
fn filter_snapshot_focus_is_origin_only() {
    use std::collections::HashSet;

    use bgp_ma::{PrefixObs, RibSnapshot};
    use chrono::TimeZone;

    use crate::commands::filter_snapshot_focus;

    let mut snap = RibSnapshot {
        as_of: Utc.with_ymd_and_hms(2026, 9, 13, 0, 30, 0).unwrap(),
        ts_start: None,
        collector: None,
        source: None,
        prefixes: Default::default(),
    };
    snap.prefixes.insert(
        "192.0.2.0/24".into(),
        PrefixObs {
            origin_asn: 65000,
            upstream_asn: Some(15169),
            as_path: vec![15169, 65000],
        },
    );
    snap.prefixes.insert(
        "198.51.100.0/24".into(),
        PrefixObs {
            origin_asn: 15169,
            upstream_asn: None,
            as_path: vec![15169],
        },
    );
    let mut focus = HashSet::new();
    focus.insert(65000);
    filter_snapshot_focus(&mut snap, &focus);
    assert!(snap.prefixes.contains_key("192.0.2.0/24"));
    assert!(
        !snap.prefixes.contains_key("198.51.100.0/24"),
        "path-contains must not retain a non-focus origin"
    );
}

#[test]
fn apply_rib_announcement_announce_and_withdraw() {
    use crate::commands::{apply_rib_announcement, RibAnnouncement};
    use bgp_rib::Rib;

    let mut rib = Rib::new();
    let prefix: ipnet::IpNet = "203.0.113.0/24".parse().unwrap();
    apply_rib_announcement(
        &mut rib,
        &RibAnnouncement {
            prefix,
            peer_asn: 1,
            withdraw: false,
            as_path: vec![65000],
            origin_asn: Some(65000),
            timestamp: 1.0,
        },
    );
    assert_eq!(rib.prefix_count(), 1);
    apply_rib_announcement(
        &mut rib,
        &RibAnnouncement {
            prefix,
            peer_asn: 1,
            withdraw: true,
            as_path: vec![],
            origin_asn: None,
            timestamp: 2.0,
        },
    );
    assert_eq!(rib.prefix_count(), 0);
}

#[test]
fn run_daily_from_fixture_snapshots() {
    use bgp_ma::{PrefixObs, RibSnapshot};
    use bgp_map::{OrgMap, OrgRecord};
    use bgp_state::{work_db_path, WorkDb};
    use chrono::TimeZone;

    use crate::args::DailyArgs;
    use crate::commands::run_daily;

    let dir = tempfile::TempDir::new().unwrap();
    let state = dir.path().to_path_buf();
    let glue_path = state.join("glue.txt");
    std::fs::write(&glue_path, "15169\n").unwrap();

    let mut map = OrgMap::new();
    map.insert(OrgRecord {
        org_id: "pdb:acme".into(),
        name: "Acme".into(),
        asns: vec![65000],
        domains: vec!["acme.example".into()],
        prefix_count_hint: None,
        external_id: None,
    });
    map.insert(OrgRecord {
        org_id: "pdb:beta".into(),
        name: "Beta".into(),
        asns: vec![65001],
        domains: vec!["beta.example".into()],
        prefix_count_hint: None,
        external_id: None,
    });
    let mut db = WorkDb::open(work_db_path(&state)).unwrap();
    db.commit_org_map(&map, Utc::now()).unwrap();
    drop(db);

    let snap_dir = state.join("snapshots");
    std::fs::create_dir_all(&snap_dir).unwrap();
    let mut before = RibSnapshot {
        as_of: Utc.with_ymd_and_hms(2026, 9, 12, 0, 30, 0).unwrap(),
        ts_start: None,
        collector: Some("fixture".into()),
        source: Some("rib".into()),
        prefixes: Default::default(),
    };
    let mut after = before.clone();
    after.as_of = Utc.with_ymd_and_hms(2026, 9, 13, 0, 30, 0).unwrap();
    for i in 0..3u8 {
        let pfx = format!("203.0.113.{i}/32");
        before.prefixes.insert(
            pfx.clone(),
            PrefixObs {
                origin_asn: 65000,
                upstream_asn: None,
                as_path: vec![65000],
            },
        );
        after.prefixes.insert(
            pfx,
            PrefixObs {
                origin_asn: 65001,
                upstream_asn: None,
                as_path: vec![65001],
            },
        );
    }
    before
        .save_json(snap_dir.join("rib-2026-09-12.json"))
        .unwrap();
    after
        .save_json(snap_dir.join("rib-2026-09-13.json"))
        .unwrap();

    run_daily(DailyArgs {
        state_dir: state.clone(),
        date: Some("2026-09-13".into()),
        collector: "fixture".into(),
        org_map: None,
        org_map_overlay: None,
        org_map_max_age_days: 14,
        glue: Some(glue_path),
        retain_days: 7,
        pair_state_days: 30,
        full: false,
        min_prefix_moves: 2,
        footprint_rel_threshold: 0.25,
        footprint_abs_threshold: 5,
        focus_asns: None,
        focus_from_org_map: true,
        no_clean: false,
        no_inbox: true,
        debug_jsonl: false,
    })
    .unwrap();

    let n: i64 = {
        let conn = rusqlite::Connection::open(work_db_path(&state)).unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM network_contact WHERE deleted_at IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(n, 1, "one attributable multi-prefix move pair");
    assert!(
        !state
            .join("events")
            .join("events-2026-09-13.jsonl")
            .exists(),
        "intermediate JSONL is off by default"
    );
}

fn tempfile_dir() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "bgp-analyzer-cli-smoke-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}
