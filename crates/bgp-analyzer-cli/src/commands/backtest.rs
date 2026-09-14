//! Historical backtest + lead-lag rows.
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;

use anyhow::{Context, Result};
use bgp_ma::{
    aggregate_pair_features, canon_pair, diff_snapshots, eval_cases, eval_cases_against_features,
    load_eval_cases, score_backtest, write_ma_events_jsonl, write_pair_features_jsonl,
    AsnPairFeature, DiffConfig, EvalCase, MaEvent, MaEventKind, RibSnapshot,
};
use bgp_map::SubjectHeuristics;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::common::{filter_snapshot_focus, load_glue, load_org_map, parse_ymd};
use super::snapshot::build_snapshot;
use crate::args::{BacktestArgs, SnapshotMode};

pub fn run_backtest(args: BacktestArgs) -> Result<()> {
    let start_day = parse_ymd(&args.start)?;
    if args.days == 0 {
        anyhow::bail!("--days must be >= 1");
    }
    if args.step_days == 0 {
        anyhow::bail!("--step-days must be >= 1");
    }
    let snap_dir = args
        .snapshot_dir
        .clone()
        .unwrap_or_else(|| args.out_dir.join("snapshots"));
    let events_dir = args.out_dir.join("events");
    std::fs::create_dir_all(&snap_dir)?;
    std::fs::create_dir_all(&events_dir)?;

    let org_map = load_org_map(&args.org_map, None, args.org_map_overlay.as_ref())?;
    let glue = load_glue(args.glue.as_ref())?;
    let cfg = DiffConfig {
        heuristics: SubjectHeuristics::default(),
        footprint_rel_threshold: args.footprint_rel_threshold,
        footprint_abs_threshold: args.footprint_abs_threshold,
    };

    let mut focus: std::collections::HashSet<u32> = std::collections::HashSet::new();
    if let Some(raw) = &args.focus_asns {
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            focus.insert(
                part.parse()
                    .with_context(|| format!("invalid --focus-asns entry `{part}`"))?,
            );
        }
    }
    if args.cases.exists() {
        for c in load_eval_cases(&args.cases)? {
            focus.insert(c.asn_a);
            if let Some(b) = c.asn_b {
                focus.insert(b);
            }
        }
    }
    info!(focus_asns = focus.len(), "snapshot focus filter");

    let mut days: Vec<NaiveDate> = Vec::new();
    let mut offset = 0i64;
    while offset < args.days as i64 {
        days.push(
            start_day
                .checked_add_signed(Duration::days(offset))
                .context("date overflow")?,
        );
        offset += args.step_days as i64;
    }
    // Always include the last day of the window if not already sampled.
    let last = start_day
        .checked_add_signed(Duration::days(args.days as i64 - 1))
        .context("date overflow")?;
    if days.last().copied() != Some(last) {
        days.push(last);
    }

    // Build or load snapshots for each sampled day.
    let mut paths: Vec<(NaiveDate, PathBuf)> = Vec::new();
    for day in &days {
        let path = snap_dir.join(format!("rib-{day}.json"));
        if path.exists() && args.skip_fetch {
            info!(%day, path = %path.display(), "reusing snapshot");
            paths.push((*day, path));
            continue;
        } else if path.exists() && !args.skip_fetch {
            // Re-fetch unless skip_fetch; still allow resume if file present to save time.
            info!(%day, path = %path.display(), "snapshot exists; reusing (pass fresh delete to refetch)");
            paths.push((*day, path));
            continue;
        }

        // RouteViews occasionally lacks a RIB on the exact sample day — try nearby days.
        let mut snap_ok = None;
        let mut used_day = *day;
        for delta in [0i64, -1, 1, -2, 2, -3, 3] {
            let try_day = match day.checked_add_signed(Duration::days(delta)) {
                Some(d) => d,
                None => continue,
            };
            let start = format!("{try_day}T00:00:00Z");
            let end = format!("{try_day}T00:30:00Z");
            info!(%day, %try_day, delta, "fetching RIB snapshot");
            match build_snapshot(
                &start,
                &end,
                &args.collector,
                SnapshotMode::Rib,
                false,
                None,
            ) {
                Ok(mut snap) => {
                    if !focus.is_empty() {
                        let before = snap.prefixes.len();
                        filter_snapshot_focus(&mut snap, &focus);
                        info!(
                            kept = snap.prefixes.len(),
                            dropped = before.saturating_sub(snap.prefixes.len()),
                            "applied focus ASN filter"
                        );
                    }
                    snap_ok = Some(snap);
                    used_day = try_day;
                    break;
                }
                Err(e) => {
                    warn!(%try_day, error = %e, "RIB fetch failed; trying adjacent day");
                }
            }
        }
        let Some(snap) = snap_ok else {
            anyhow::bail!("no RIB snapshot available near {day} (±3 days)");
        };
        // Always store under the planned sample day name so resume paths stay stable.
        snap.save_json(&path)?;
        info!(
            planned = %day,
            used = %used_day,
            path = %path.display(),
            prefixes = snap.prefixes.len(),
            as_of = %snap.as_of,
            "wrote day snapshot"
        );
        paths.push((*day, path));
    }

    // Consecutive diffs between sampled days.
    let mut all_events: Vec<MaEvent> = Vec::new();
    for w in paths.windows(2) {
        let (day_a, path_a) = &w[0];
        let (day_b, path_b) = &w[1];
        let before = RibSnapshot::load_json(path_a)?;
        let after = RibSnapshot::load_json(path_b)?;
        let events = diff_snapshots(&before, &after, &org_map, &glue, &cfg);
        let out = events_dir.join(format!("events-{day_a}-to-{day_b}.jsonl"));
        write_ma_events_jsonl(&out, &events)?;
        info!(
            before = %day_a,
            after = %day_b,
            events = events.len(),
            path = %out.display(),
            "day diff complete"
        );
        all_events.extend(events);
    }

    let all_path = events_dir.join("all-events.jsonl");
    write_ma_events_jsonl(&all_path, &all_events)?;

    let features = aggregate_pair_features(&all_events);
    let feat_path = args.out_dir.join("pair-features.jsonl");
    write_pair_features_jsonl(&feat_path, &features)?;
    info!(
        pairs = features.len(),
        path = %feat_path.display(),
        "wrote pair features"
    );

    // Eval wiring (empty cases → no-op success).
    if args.cases.exists() {
        let cases = load_eval_cases(&args.cases)?;
        // Score only cases overlapping this backtest window.
        let win_start = days
            .first()
            .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc())
            .unwrap();
        let win_end = days
            .last()
            .map(|d| d.and_hms_opt(23, 59, 59).unwrap().and_utc())
            .unwrap();
        let scoped: Vec<_> = cases
            .into_iter()
            .filter(|c| c.window_end >= win_start && c.window_start <= win_end)
            .collect();
        if !scoped.is_empty() {
            let report = score_backtest(&scoped, &all_events, &features);
            let report_path = args.out_dir.join("eval-report.json");
            let file = File::create(&report_path)
                .with_context(|| format!("creating {}", report_path.display()))?;
            serde_json::to_writer_pretty(BufWriter::new(file), &report)?;
            let lead_lag = build_lead_lag_rows(&scoped, &features, &all_events);
            let ll_path = args.out_dir.join("lead-lag-summary.json");
            let ll_file = File::create(&ll_path)
                .with_context(|| format!("creating {}", ll_path.display()))?;
            serde_json::to_writer_pretty(BufWriter::new(ll_file), &lead_lag)?;
            info!(
                path = %report_path.display(),
                event_passed = report.event_passed,
                event_failed = report.event_failed,
                feature_passed = report.feature_passed,
                feature_failed = report.feature_failed,
                "backtest eval report"
            );
            for r in &report.feature_results {
                if r.passed {
                    info!(id = %r.id, hit = r.hit, detail = ?r.matched_detail, "FEATURE PASS");
                } else {
                    warn!(id = %r.id, hit = r.hit, "FEATURE FAIL");
                }
            }
            // Do not hard-fail the backtest on label misses — lead-lag study needs the corpus.
            if report.feature_failed > 0 {
                warn!(
                    failed = report.feature_failed,
                    total = scoped.len(),
                    "some cases failed at pair-feature level (see lead-lag-summary.json)"
                );
            }
        } else {
            info!("no eval cases overlap this backtest window; skipping label score");
        }
    }

    info!(
        samples = days.len(),
        step_days = args.step_days,
        diffs = paths.len().saturating_sub(1),
        events = all_events.len(),
        pairs = features.len(),
        "backtest complete"
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeadLagRow {
    id: String,
    expect_hit: bool,
    expect_kind: String,
    asn_a: u32,
    asn_b: Option<u32>,
    announce_end: String,
    feature_hit: bool,
    event_hit: bool,
    /// True if any of prefix_move / new_adj / upstream_converge for the labeled pair in-window.
    pair_contact_hit: bool,
    /// True if target ASN (asn_b, else asn_a) had a footprint_step in-window.
    target_footprint_hit: bool,
    passed_feature: bool,
    lead_days: Option<i64>,
    /// Histogram bucket: >365 | 181-365 | 91-180 | 31-90 | 8-30 | 1-7 | 0 | miss
    horizon_bucket: String,
    first_seen: Option<String>,
    detail: Option<String>,
}

pub fn horizon_bucket(lead_days: Option<i64>, contact: bool) -> String {
    if !contact {
        return "miss".to_string();
    }
    match lead_days {
        None => "miss".to_string(),
        Some(d) if d > 365 => ">365".to_string(),
        Some(d) if d >= 181 => "181-365".to_string(),
        Some(d) if d >= 91 => "91-180".to_string(),
        Some(d) if d >= 31 => "31-90".to_string(),
        Some(d) if d >= 8 => "8-30".to_string(),
        Some(d) if d >= 1 => "1-7".to_string(),
        Some(0) => "0".to_string(),
        // Contact after announce day (post-announce window).
        Some(_) => "post-announce".to_string(),
    }
}

/// Announce calendar day: prefer `announce=YYYY-MM-DD` in notes; else window_end.
pub fn announce_day(case: &EvalCase) -> chrono::NaiveDate {
    for part in case.notes.split_whitespace() {
        if let Some(raw) = part.strip_prefix("announce=") {
            if let Ok(d) = chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
                return d;
            }
        }
    }
    case.window_end.date_naive()
}

pub fn pair_contact_in_window(
    case: &EvalCase,
    features: &[AsnPairFeature],
    events: &[MaEvent],
) -> (bool, Option<i64>, Option<String>) {
    let Some(b) = case.asn_b else {
        return (false, None, None);
    };
    let announce = announce_day(case);
    let (lo, hi) = canon_pair(case.asn_a, b);
    let mut first: Option<DateTime<Utc>> = None;

    if let Some(f) = features.iter().find(|f| f.asn_lo == lo && f.asn_hi == hi) {
        let overlaps = !(f.last_seen < case.window_start || f.first_seen > case.window_end);
        let contact = overlaps
            && (f.prefix_move_days > 0 || f.new_adj_days > 0 || f.upstream_converge_days > 0);
        if contact {
            // Clamp first_seen into window for lead calculation.
            let fs = if f.first_seen < case.window_start {
                case.window_start
            } else {
                f.first_seen
            };
            first = Some(fs);
        }
    }

    for ev in events {
        if ev.timestamp < case.window_start || ev.timestamp > case.window_end {
            continue;
        }
        let kind_ok = matches!(
            ev.kind,
            MaEventKind::PrefixMove | MaEventKind::NewAdj | MaEventKind::UpstreamConverge
        );
        if !kind_ok {
            continue;
        }
        if !matches!(
            (ev.asn_a, ev.asn_b),
            (Some(a), Some(bb)) if (a == case.asn_a && bb == b) || (a == b && bb == case.asn_a)
        ) {
            continue;
        }
        first = Some(match first {
            Some(prev) if prev <= ev.timestamp => prev,
            _ => ev.timestamp,
        });
    }

    match first {
        Some(fs) => {
            let lead = (announce - fs.date_naive()).num_days();
            (true, Some(lead), Some(fs.to_rfc3339()))
        }
        None => (false, None, None),
    }
}

pub fn target_footprint_hit(case: &EvalCase, events: &[MaEvent]) -> bool {
    let target = case.asn_b.unwrap_or(case.asn_a);
    events.iter().any(|ev| {
        ev.kind == MaEventKind::FootprintStep
            && ev.timestamp >= case.window_start
            && ev.timestamp <= case.window_end
            && ev.asn_a == Some(target)
    })
}

pub fn build_lead_lag_rows(
    cases: &[EvalCase],
    features: &[AsnPairFeature],
    events: &[MaEvent],
) -> Vec<LeadLagRow> {
    let feat_results = eval_cases_against_features(cases, features);
    let event_results = eval_cases(cases, events);
    cases
        .iter()
        .zip(feat_results.iter())
        .zip(event_results.iter())
        .map(|((case, fr), er)| {
            let (pair_contact_hit, lead_days, first_seen) =
                pair_contact_in_window(case, features, events);
            let target_fp = target_footprint_hit(case, events);
            let kind = serde_json::to_value(case.expect_kind)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| format!("{:?}", case.expect_kind));
            LeadLagRow {
                id: case.id.clone(),
                expect_hit: case.expect_hit,
                expect_kind: kind,
                asn_a: case.asn_a,
                asn_b: case.asn_b,
                announce_end: case.window_end.to_rfc3339(),
                feature_hit: fr.hit,
                event_hit: er.hit,
                pair_contact_hit,
                target_footprint_hit: target_fp,
                passed_feature: fr.passed,
                lead_days,
                horizon_bucket: horizon_bucket(lead_days, pair_contact_hit),
                first_seen,
                detail: fr.matched_detail.clone(),
            }
        })
        .collect()
}
