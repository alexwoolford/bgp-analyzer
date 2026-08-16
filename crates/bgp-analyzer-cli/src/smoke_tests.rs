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
    assert_eq!(back, env);
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
