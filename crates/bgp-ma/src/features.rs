//! Pair features and sparse daily filters for BGP network-contact signals.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{eval_cases, EvalCase, EvalCaseResult, MaEvent, MaEventKind};

/// Canonical undirected ASN pair (lo, hi).
pub type AsnPair = (u32, u32);

pub fn canon_pair(a: u32, b: u32) -> AsnPair {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Aggregated contact features for an ASN pair across one or more day diffs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AsnPairFeature {
    pub asn_lo: u32,
    pub asn_hi: u32,
    #[serde(default)]
    pub org_lo: Option<String>,
    #[serde(default)]
    pub org_hi: Option<String>,
    /// Distinct calendar days with at least one `prefix_move` between the pair.
    pub prefix_move_days: u32,
    /// Distinct prefixes that moved between the pair.
    pub prefixes_moved: u32,
    pub new_adj_days: u32,
    pub upstream_converge_days: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Inclusive span in whole days (`last_seen - first_seen`).
    pub persistence_days: i64,
    /// Simple ranking score for diligence triage (not a deal probability).
    pub score: i64,
}

#[derive(Default)]
struct Acc {
    org_lo: Option<String>,
    org_hi: Option<String>,
    prefix_move_days: HashSet<String>,
    prefixes: HashSet<String>,
    new_adj_days: HashSet<String>,
    upstream_days: HashSet<String>,
    first: Option<DateTime<Utc>>,
    last: Option<DateTime<Utc>>,
}

fn day_key(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%d").to_string()
}

fn touch(acc: &mut Acc, ts: DateTime<Utc>) {
    match acc.first {
        None => acc.first = Some(ts),
        Some(f) if ts < f => acc.first = Some(ts),
        _ => {}
    }
    match acc.last {
        None => acc.last = Some(ts),
        Some(l) if ts > l => acc.last = Some(ts),
        _ => {}
    }
}

fn assign_orgs(acc: &mut Acc, pair: AsnPair, ev: &MaEvent) {
    let (Some(a), Some(b)) = (ev.asn_a, ev.asn_b) else {
        return;
    };
    if a == pair.0 && b == pair.1 {
        if acc.org_lo.is_none() {
            acc.org_lo = ev.org_a.clone();
        }
        if acc.org_hi.is_none() {
            acc.org_hi = ev.org_b.clone();
        }
    } else if a == pair.1 && b == pair.0 {
        if acc.org_lo.is_none() {
            acc.org_lo = ev.org_b.clone();
        }
        if acc.org_hi.is_none() {
            acc.org_hi = ev.org_a.clone();
        }
    }
}

/// Aggregate day-diff events into ASN-pair features (persistence, prefixes moved, score).
pub fn aggregate_pair_features(events: &[MaEvent]) -> Vec<AsnPairFeature> {
    let mut map: HashMap<AsnPair, Acc> = HashMap::new();
    for ev in events {
        let (Some(a), Some(b)) = (ev.asn_a, ev.asn_b) else {
            continue;
        };
        if a == b {
            continue;
        }
        let pair = canon_pair(a, b);
        let acc = map.entry(pair).or_default();
        assign_orgs(acc, pair, ev);
        touch(acc, ev.timestamp);
        let dk = day_key(ev.timestamp);
        match ev.kind {
            MaEventKind::PrefixMove => {
                acc.prefix_move_days.insert(dk);
                if let Some(ref p) = ev.prefix {
                    acc.prefixes.insert(p.clone());
                }
            }
            MaEventKind::NewAdj => {
                acc.new_adj_days.insert(dk);
            }
            MaEventKind::UpstreamConverge => {
                acc.upstream_days.insert(dk);
            }
            MaEventKind::FootprintStep => {}
        }
    }

    let mut out: Vec<AsnPairFeature> = map
        .into_iter()
        .filter_map(|(pair, acc)| {
            let first = acc.first?;
            let last = acc.last?;
            let prefixes_moved = acc.prefixes.len() as u32;
            let prefix_move_days = acc.prefix_move_days.len() as u32;
            let new_adj_days = acc.new_adj_days.len() as u32;
            let upstream_converge_days = acc.upstream_days.len() as u32;
            let persistence_days = (last - first).num_days();
            let score = i64::from(prefixes_moved) * 10
                + i64::from(prefix_move_days) * 5
                + i64::from(new_adj_days)
                + i64::from(upstream_converge_days)
                + persistence_days.max(0);
            Some(AsnPairFeature {
                asn_lo: pair.0,
                asn_hi: pair.1,
                org_lo: acc.org_lo,
                org_hi: acc.org_hi,
                prefix_move_days,
                prefixes_moved,
                new_adj_days,
                upstream_converge_days,
                first_seen: first,
                last_seen: last,
                persistence_days,
                score,
            })
        })
        .collect();
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.asn_lo.cmp(&b.asn_lo)));
    out
}

/// Daily sparse filter: keep high-signal events only.
#[derive(Debug, Clone)]
pub struct SparseConfig {
    /// Keep `prefix_move` when the same ASN pair moves at least this many prefixes that day.
    pub min_prefix_moves_per_pair_day: u32,
    pub keep_new_adj: bool,
    pub keep_upstream_converge: bool,
    pub keep_footprint_step: bool,
}

impl Default for SparseConfig {
    fn default() -> Self {
        Self {
            min_prefix_moves_per_pair_day: 2,
            keep_new_adj: false,
            keep_upstream_converge: false,
            keep_footprint_step: false,
        }
    }
}

/// Filter events to a sparse diligence set (default: multi-prefix moves only).
pub fn filter_sparse_events(events: &[MaEvent], cfg: &SparseConfig) -> Vec<MaEvent> {
    let mut move_counts: HashMap<(AsnPair, String), u32> = HashMap::new();
    for ev in events {
        if ev.kind != MaEventKind::PrefixMove {
            continue;
        }
        let (Some(a), Some(b)) = (ev.asn_a, ev.asn_b) else {
            continue;
        };
        let key = (canon_pair(a, b), day_key(ev.timestamp));
        *move_counts.entry(key).or_insert(0) += 1;
    }

    events
        .iter()
        .filter(|ev| match ev.kind {
            MaEventKind::PrefixMove => {
                let (Some(a), Some(b)) = (ev.asn_a, ev.asn_b) else {
                    return false;
                };
                let key = (canon_pair(a, b), day_key(ev.timestamp));
                move_counts.get(&key).copied().unwrap_or(0) >= cfg.min_prefix_moves_per_pair_day
            }
            MaEventKind::NewAdj => cfg.keep_new_adj,
            MaEventKind::UpstreamConverge => cfg.keep_upstream_converge,
            MaEventKind::FootprintStep => cfg.keep_footprint_step,
        })
        .cloned()
        .collect()
}

/// Score eval cases against pair features (hit if pair appears with relevant activity).
pub fn eval_cases_against_features(
    cases: &[EvalCase],
    features: &[AsnPairFeature],
) -> Vec<EvalCaseResult> {
    cases
        .iter()
        .map(|case| {
            let matched = features.iter().find(|f| feature_matches_case(f, case));
            let hit = matched.is_some();
            EvalCaseResult {
                id: case.id.clone(),
                hit,
                passed: hit == case.expect_hit,
                matched_detail: matched.map(|f| {
                    format!(
                        "score={} prefixes_moved={} prefix_move_days={} persistence_days={}",
                        f.score, f.prefixes_moved, f.prefix_move_days, f.persistence_days
                    )
                }),
            }
        })
        .collect()
}

fn feature_matches_case(f: &AsnPairFeature, case: &EvalCase) -> bool {
    let pair_ok = match case.asn_b {
        Some(b) => {
            let (lo, hi) = canon_pair(case.asn_a, b);
            f.asn_lo == lo && f.asn_hi == hi
        }
        None => f.asn_lo == case.asn_a || f.asn_hi == case.asn_a,
    };
    if !pair_ok {
        return false;
    }
    // Window overlap with feature span.
    if f.last_seen < case.window_start || f.first_seen > case.window_end {
        return false;
    }
    match case.expect_kind {
        MaEventKind::PrefixMove => f.prefix_move_days > 0,
        MaEventKind::NewAdj => f.new_adj_days > 0,
        MaEventKind::UpstreamConverge => f.upstream_converge_days > 0,
        MaEventKind::FootprintStep => true,
    }
}

/// Combined backtest report: raw event eval + pair-feature eval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacktestEvalReport {
    pub event_results: Vec<EvalCaseResult>,
    pub feature_results: Vec<EvalCaseResult>,
    pub event_hits: usize,
    pub event_misses: usize,
    pub feature_hits: usize,
    pub feature_misses: usize,
    pub event_passed: usize,
    pub event_failed: usize,
    pub feature_passed: usize,
    pub feature_failed: usize,
}

pub fn score_backtest(
    cases: &[EvalCase],
    events: &[MaEvent],
    features: &[AsnPairFeature],
) -> BacktestEvalReport {
    let event_results = eval_cases(cases, events);
    let feature_results = eval_cases_against_features(cases, features);
    let event_hits = event_results.iter().filter(|r| r.hit).count();
    let feature_hits = feature_results.iter().filter(|r| r.hit).count();
    let event_passed = event_results.iter().filter(|r| r.passed).count();
    let feature_passed = feature_results.iter().filter(|r| r.passed).count();
    BacktestEvalReport {
        event_misses: event_results.len().saturating_sub(event_hits),
        feature_misses: feature_results.len().saturating_sub(feature_hits),
        event_failed: event_results.len().saturating_sub(event_passed),
        feature_failed: feature_results.len().saturating_sub(feature_passed),
        event_hits,
        feature_hits,
        event_passed,
        feature_passed,
        event_results,
        feature_results,
    }
}

pub fn write_pair_features_jsonl(
    path: impl AsRef<Path>,
    features: &[AsnPairFeature],
) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file =
        std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = std::io::BufWriter::new(file);
    use std::io::Write;
    for f in features {
        serde_json::to_writer(&mut w, f)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

pub fn write_ma_events_jsonl(path: impl AsRef<Path>, events: &[MaEvent]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file =
        std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = std::io::BufWriter::new(file);
    use std::io::Write;
    for ev in events {
        serde_json::to_writer(&mut w, ev)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn move_ev(day: i64, a: u32, b: u32, prefix: &str) -> MaEvent {
        MaEvent {
            kind: MaEventKind::PrefixMove,
            timestamp: Utc.timestamp_opt(day * 86400, 0).unwrap(),
            org_a: Some("a".into()),
            org_b: Some("b".into()),
            asn_a: Some(a),
            asn_b: Some(b),
            domains_a: vec![],
            domains_b: vec![],
            prefix: Some(prefix.into()),
            detail: format!("origin {a} -> {b}"),
        }
    }

    #[test]
    fn aggregates_persistence_and_prefixes() {
        let events = vec![
            move_ev(1, 65000, 65001, "203.0.113.0/24"),
            move_ev(1, 65000, 65001, "203.0.113.1/32"),
            move_ev(3, 65001, 65000, "198.51.100.0/24"),
        ];
        let feats = aggregate_pair_features(&events);
        assert_eq!(feats.len(), 1);
        assert_eq!(feats[0].prefixes_moved, 3);
        assert_eq!(feats[0].prefix_move_days, 2);
        assert_eq!(feats[0].persistence_days, 2);
        assert!(feats[0].score > 0);
    }

    #[test]
    fn sparse_keeps_multi_prefix_moves_only() {
        let events = vec![
            move_ev(1, 65000, 65001, "203.0.113.0/24"),
            move_ev(1, 65000, 65001, "203.0.113.1/32"),
            move_ev(1, 65002, 65003, "198.51.100.0/24"),
        ];
        let sparse = filter_sparse_events(&events, &SparseConfig::default());
        assert_eq!(sparse.len(), 2);
        assert!(sparse.iter().all(|e| {
            matches!(
                (e.asn_a, e.asn_b),
                (Some(65000), Some(65001)) | (Some(65001), Some(65000))
            )
        }));
    }
}
