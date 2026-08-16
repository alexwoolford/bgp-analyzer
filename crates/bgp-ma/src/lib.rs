//! BGP M&A network-contact events from watchlist-constrained RIB snapshots.

mod features;
mod signal;

pub use features::{
    aggregate_pair_features, canon_pair, eval_cases_against_features, filter_sparse_events,
    score_backtest, write_ma_events_jsonl, write_pair_features_jsonl, AsnPair, AsnPairFeature,
    BacktestEvalReport, SparseConfig,
};
pub use signal::{
    append_inbox_jsonl, build_signals, clean_drop_reason, filter_clean_features, leasing_set,
    write_signals_jsonl, CleanDropReason, PairStateEntry, PairStateStore, SignalEnvelope,
    DEFAULT_LEASING_ASNS,
};

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

use anyhow::{Context, Result};
use bgp_map::{GlueSet, OrgMap, SubjectHeuristics};
use bgp_rib::Rib;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tracing::info;

/// Kind of BGP M&A network-contact event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaEventKind {
    /// Prefix previously originated by org A now originated by org B.
    PrefixMove,
    /// Watchlist ASN changed its immediate upstream toward another watchlist org's provider pattern.
    UpstreamConverge,
    /// First observed AS_PATH adjacency between two non-glue watchlist ASNs.
    NewAdj,
    /// Large persistent change in announced prefix count for a subject ASN/org.
    FootprintStep,
}

/// BGP M&A network-contact event.
///
/// Events carry ASN, optional org id, and domain attributes for downstream consumers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MaEvent {
    pub kind: MaEventKind,
    pub timestamp: DateTime<Utc>,
    pub org_a: Option<String>,
    pub org_b: Option<String>,
    pub asn_a: Option<u32>,
    pub asn_b: Option<u32>,
    /// Domains attributed to org_a / asn_a (many-to-many attribute, not identity).
    #[serde(default)]
    pub domains_a: Vec<String>,
    #[serde(default)]
    pub domains_b: Vec<String>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub detail: String,
}

/// Per-prefix collapsed observation (origin + immediate upstream).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefixObs {
    pub origin_asn: u32,
    /// ASN immediately before the origin in the wire AS_PATH (provider/peer of origin).
    pub upstream_asn: Option<u32>,
    pub as_path: Vec<u32>,
}

/// Point-in-time origin view used for daily diffs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RibSnapshot {
    /// BGP window end (or RIB dump time), not wall-clock build time.
    pub as_of: DateTime<Utc>,
    /// BGP window start used when building this snapshot (audit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts_start: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector: Option<String>,
    /// `"rib"` or `"updates"` — how the snapshot was built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// prefix string → observation
    pub prefixes: HashMap<String, PrefixObs>,
}

impl RibSnapshot {
    pub fn from_rib(rib: &Rib, as_of: DateTime<Utc>) -> Self {
        let mut prefixes = HashMap::new();
        for (prefix, peers) in rib.iter() {
            // Prefer the observation with the longest AS_PATH (more context); tie-break by peer asn.
            let mut best: Option<&bgp_rib::RouteEntry> = None;
            for entry in peers.values() {
                best = match best {
                    None => Some(entry),
                    Some(cur) => {
                        let cur_len = rib.interner.as_path(cur.as_path_id).map(|p| p.len()).unwrap_or(0);
                        let new_len = rib
                            .interner
                            .as_path(entry.as_path_id)
                            .map(|p| p.len())
                            .unwrap_or(0);
                        if new_len > cur_len
                            || (new_len == cur_len && entry.peer_asn < cur.peer_asn)
                        {
                            Some(entry)
                        } else {
                            Some(cur)
                        }
                    }
                };
            }
            let Some(entry) = best else { continue };
            let Some(origin) = entry.origin_asn else { continue };
            let path = rib
                .interner
                .as_path(entry.as_path_id)
                .unwrap_or(&[])
                .to_vec();
            let upstream = upstream_of_origin(&path, origin);
            prefixes.insert(
                prefix.to_string(),
                PrefixObs {
                    origin_asn: origin,
                    upstream_asn: upstream,
                    as_path: path,
                },
            );
        }
        Self {
            as_of,
            ts_start: None,
            collector: None,
            source: None,
            prefixes,
        }
    }

    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let file = File::create(path.as_ref())
            .with_context(|| format!("creating {}", path.as_ref().display()))?;
        serde_json::to_writer(BufWriter::new(file), self)?;
        Ok(())
    }

    pub fn load_json(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref())
            .with_context(|| format!("opening {}", path.as_ref().display()))?;
        Ok(serde_json::from_reader(BufReader::new(file))?)
    }

    pub fn prefix_count_by_origin(&self) -> HashMap<u32, u32> {
        let mut counts = HashMap::new();
        for obs in self.prefixes.values() {
            *counts.entry(obs.origin_asn).or_insert(0) += 1;
        }
        counts
    }
}

fn upstream_of_origin(as_path: &[u32], origin: u32) -> Option<u32> {
    let mut path: Vec<u32> = as_path.to_vec();
    path.dedup();
    if path.last().copied() != Some(origin) {
        // origin may still be last after sets; fall back to last hop before final.
        if let Some(pos) = path.iter().rposition(|&a| a == origin) {
            if pos > 0 {
                return Some(path[pos - 1]);
            }
        }
        return None;
    }
    if path.len() >= 2 {
        Some(path[path.len() - 2])
    } else {
        None
    }
}

/// Watchlist-constrained adjacency pairs (sorted tuple).
fn watchlist_adjacencies(path: &[u32], subjects: &HashSet<u32>, glue: &GlueSet) -> HashSet<(u32, u32)> {
    let mut path: Vec<u32> = path.to_vec();
    path.dedup();
    let mut out = HashSet::new();
    for w in path.windows(2) {
        let a = w[0];
        let b = w[1];
        if a == b {
            continue;
        }
        if glue.contains(a) || glue.contains(b) {
            continue;
        }
        if subjects.contains(&a) && subjects.contains(&b) {
            let pair = if a < b { (a, b) } else { (b, a) };
            out.insert(pair);
        }
    }
    out
}

/// Diff parameters.
#[derive(Debug, Clone)]
pub struct DiffConfig {
    pub heuristics: SubjectHeuristics,
    /// Relative footprint change (e.g. 0.25 = 25%) to emit FootprintStep.
    pub footprint_rel_threshold: f64,
    /// Absolute prefix-count delta floor for FootprintStep.
    pub footprint_abs_threshold: u32,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self {
            heuristics: SubjectHeuristics::default(),
            footprint_rel_threshold: 0.25,
            footprint_abs_threshold: 5,
        }
    }
}

/// Diff two snapshots into standalone M&A events.
pub fn diff_snapshots(
    before: &RibSnapshot,
    after: &RibSnapshot,
    org_map: &OrgMap,
    glue: &GlueSet,
    cfg: &DiffConfig,
) -> Vec<MaEvent> {
    let subjects = org_map.subject_asns(glue, &cfg.heuristics);
    let mut events = Vec::new();
    let ts = after.as_of;

    // --- prefix moves (subject origins only) ---
    for (prefix, after_obs) in &after.prefixes {
        let Some(before_obs) = before.prefixes.get(prefix) else {
            continue;
        };
        if before_obs.origin_asn == after_obs.origin_asn {
            continue;
        }
        let a_subject = subjects.contains(&before_obs.origin_asn);
        let b_subject = subjects.contains(&after_obs.origin_asn);
        if !(a_subject || b_subject) {
            continue;
        }
        // Skip moves that are only glue↔glue.
        if glue.contains(before_obs.origin_asn) && glue.contains(after_obs.origin_asn) {
            continue;
        }
        let org_a = org_map.org_for_asn(before_obs.origin_asn);
        let org_b = org_map.org_for_asn(after_obs.origin_asn);
        events.push(MaEvent {
            kind: MaEventKind::PrefixMove,
            timestamp: ts,
            org_a: org_a.map(|o| o.org_id.clone()),
            org_b: org_b.map(|o| o.org_id.clone()),
            asn_a: Some(before_obs.origin_asn),
            asn_b: Some(after_obs.origin_asn),
            domains_a: org_a.map(|o| o.domains.clone()).unwrap_or_default(),
            domains_b: org_b.map(|o| o.domains.clone()).unwrap_or_default(),
            prefix: Some(prefix.clone()),
            detail: format!(
                "origin {} -> {}",
                before_obs.origin_asn, after_obs.origin_asn
            ),
        });
    }

    // --- upstream convergence for subject origins ---
    let mut before_up: HashMap<u32, HashSet<u32>> = HashMap::new();
    let mut after_up: HashMap<u32, HashSet<u32>> = HashMap::new();
    for obs in before.prefixes.values() {
        if !subjects.contains(&obs.origin_asn) {
            continue;
        }
        if let Some(u) = obs.upstream_asn {
            before_up.entry(obs.origin_asn).or_default().insert(u);
        }
    }
    for obs in after.prefixes.values() {
        if !subjects.contains(&obs.origin_asn) {
            continue;
        }
        if let Some(u) = obs.upstream_asn {
            after_up.entry(obs.origin_asn).or_default().insert(u);
        }
    }
    for (origin, after_set) in &after_up {
        let before_set = before_up.get(origin).cloned().unwrap_or_default();
        let new_upstreams: Vec<u32> = after_set.difference(&before_set).copied().collect();
        if new_upstreams.is_empty() {
            continue;
        }
        // Emit when a new upstream is itself a subject ASN (convergence toward another watchlist network)
        // or belongs to a mapped org.
        for up in new_upstreams {
            if glue.contains(up) && !subjects.contains(&up) {
                // Changing toward pure transit is weaker; still record if origin is subject
                // only when the upstream maps to a non-glue org — skip pure glue.
                if org_map.org_for_asn(up).is_none() || glue.contains(up) {
                    continue;
                }
            }
            let org_a = org_map.org_for_asn(*origin);
            let org_b = org_map.org_for_asn(up);
            if org_a.is_some() && org_b.is_some() && org_a.map(|o| &o.org_id) == org_b.map(|o| &o.org_id)
            {
                continue;
            }
            events.push(MaEvent {
                kind: MaEventKind::UpstreamConverge,
                timestamp: ts,
                org_a: org_a.map(|o| o.org_id.clone()),
                org_b: org_b.map(|o| o.org_id.clone()),
                asn_a: Some(*origin),
                asn_b: Some(up),
                domains_a: org_a.map(|o| o.domains.clone()).unwrap_or_default(),
                domains_b: org_b.map(|o| o.domains.clone()).unwrap_or_default(),
                prefix: None,
                detail: format!("origin {origin} gained upstream {up}"),
            });
        }
    }

    // --- new watchlist adjacencies ---
    let mut before_adj = HashSet::new();
    let mut after_adj = HashSet::new();
    for obs in before.prefixes.values() {
        before_adj.extend(watchlist_adjacencies(&obs.as_path, &subjects, glue));
    }
    for obs in after.prefixes.values() {
        after_adj.extend(watchlist_adjacencies(&obs.as_path, &subjects, glue));
    }
    for (a, b) in after_adj.difference(&before_adj) {
        let org_a = org_map.org_for_asn(*a);
        let org_b = org_map.org_for_asn(*b);
        events.push(MaEvent {
            kind: MaEventKind::NewAdj,
            timestamp: ts,
            org_a: org_a.map(|o| o.org_id.clone()),
            org_b: org_b.map(|o| o.org_id.clone()),
            asn_a: Some(*a),
            asn_b: Some(*b),
            domains_a: org_a.map(|o| o.domains.clone()).unwrap_or_default(),
            domains_b: org_b.map(|o| o.domains.clone()).unwrap_or_default(),
            prefix: None,
            detail: format!("new subject adjacency {a}-{b}"),
        });
    }

    // --- footprint step changes ---
    let before_counts = before.prefix_count_by_origin();
    let after_counts = after.prefix_count_by_origin();
    let mut origins: HashSet<u32> = before_counts.keys().copied().collect();
    origins.extend(after_counts.keys().copied());
    for origin in origins {
        if !subjects.contains(&origin) {
            continue;
        }
        let b = *before_counts.get(&origin).unwrap_or(&0);
        let a = *after_counts.get(&origin).unwrap_or(&0);
        let delta = a as i64 - b as i64;
        if delta.abs() < cfg.footprint_abs_threshold as i64 {
            continue;
        }
        let base = b.max(1) as f64;
        let rel = delta.abs() as f64 / base;
        if rel < cfg.footprint_rel_threshold && delta.abs() < (cfg.footprint_abs_threshold as i64 * 4)
        {
            continue;
        }
        let org = org_map.org_for_asn(origin);
        events.push(MaEvent {
            kind: MaEventKind::FootprintStep,
            timestamp: ts,
            org_a: org.map(|o| o.org_id.clone()),
            org_b: None,
            asn_a: Some(origin),
            asn_b: None,
            domains_a: org.map(|o| o.domains.clone()).unwrap_or_default(),
            domains_b: vec![],
            prefix: None,
            detail: format!("prefix_count {b} -> {a} (delta {delta})"),
        });
    }

    info!(events = events.len(), "M&A snapshot diff complete");
    events
}

/// Parse a prefix string into IpNet (helper for callers).
pub fn parse_prefix(s: &str) -> Result<IpNet> {
    Ok(s.parse()?)
}

/// Eval case: known-positive (or known-negative) expectation against events / features.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalCase {
    pub id: String,
    pub expect_kind: MaEventKind,
    pub asn_a: u32,
    #[serde(default)]
    pub asn_b: Option<u32>,
    #[serde(default)]
    pub prefix: Option<String>,
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    /// When false, a hit is a false positive (negative control).
    #[serde(default = "default_true")]
    pub expect_hit: bool,
    #[serde(default)]
    pub notes: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvalCaseResult {
    pub id: String,
    /// Whether a matching event/feature was found.
    pub hit: bool,
    /// Whether the outcome matches `expect_hit`.
    pub passed: bool,
    #[serde(default)]
    pub matched_detail: Option<String>,
}

/// Report hit/miss for each case against emitted events (real data only; no synthesis).
pub fn eval_cases(cases: &[EvalCase], events: &[MaEvent]) -> Vec<EvalCaseResult> {
    cases
        .iter()
        .map(|case| {
            let matched = events.iter().find(|ev| event_matches_case(ev, case));
            let hit = matched.is_some();
            EvalCaseResult {
                id: case.id.clone(),
                hit,
                passed: hit == case.expect_hit,
                matched_detail: matched.map(|ev| ev.detail.clone()),
            }
        })
        .collect()
}

fn event_matches_case(ev: &MaEvent, case: &EvalCase) -> bool {
    if ev.kind != case.expect_kind {
        return false;
    }
    if ev.timestamp < case.window_start || ev.timestamp > case.window_end {
        return false;
    }
    if let Some(ref want) = case.prefix {
        if ev.prefix.as_deref() != Some(want.as_str()) {
            return false;
        }
    }
    match case.asn_b {
        Some(b) => asn_pair_matches(ev.asn_a, ev.asn_b, case.asn_a, b),
        None => ev.asn_a == Some(case.asn_a),
    }
}

fn asn_pair_matches(
    ev_a: Option<u32>,
    ev_b: Option<u32>,
    case_a: u32,
    case_b: u32,
) -> bool {
    match (ev_a, ev_b) {
        (Some(a), Some(b)) => (a == case_a && b == case_b) || (a == case_b && b == case_a),
        _ => false,
    }
}

/// Load eval cases from JSONL (one [`EvalCase`] per non-empty line).
pub fn load_eval_cases(path: impl AsRef<Path>) -> Result<Vec<EvalCase>> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let mut cases = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let case: EvalCase = serde_json::from_str(line)
            .with_context(|| format!("parsing eval case at {}:{}", path.display(), i + 1))?;
        cases.push(case);
    }
    Ok(cases)
}

/// Load M&A events from JSONL.
pub fn load_ma_events(path: impl AsRef<Path>) -> Result<Vec<MaEvent>> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let mut events = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let ev: MaEvent = serde_json::from_str(line)
            .with_context(|| format!("parsing event at {}:{}", path.display(), i + 1))?;
        events.push(ev);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_map::{OrgRecord, SubjectHeuristics};
    use bgp_rib::{Rib, RouteEntry, RpkiState};
    use chrono::TimeZone;

    fn org_map() -> OrgMap {
        let mut m = OrgMap::new();
        m.insert(OrgRecord {
            org_id: "acme".into(),
            name: "Acme".into(),
            asns: vec![65000],
            domains: vec!["acme.com".into()],
            prefix_count_hint: Some(10),
            external_id: None,
        });
        m.insert(OrgRecord {
            org_id: "beta".into(),
            name: "Beta".into(),
            asns: vec![65001],
            domains: vec!["beta.io".into()],
            prefix_count_hint: Some(5),
            external_id: None,
        });
        m
    }

    fn entry(rib: &mut Rib, path: &[u32], peer: u32, origin: u32) -> RouteEntry {
        let id = rib.interner.intern_as_path(path);
        RouteEntry {
            origin_asn: Some(origin),
            as_path_id: id,
            peer_asn: peer,
            communities_id: None,
            rpki: RpkiState::Unknown,
            timestamp: 1.0,
        }
    }

    #[test]
    fn detects_prefix_move_between_subjects() {
        let mut rib_b = Rib::new();
        let p: IpNet = "203.0.113.0/24".parse().unwrap();
        let e = entry(&mut rib_b, &[1, 65000], 1, 65000);
        rib_b.announce(p, e);
        let before = RibSnapshot::from_rib(&rib_b, Utc.timestamp_opt(1, 0).unwrap());

        let mut rib_a = Rib::new();
        let e = entry(&mut rib_a, &[1, 65001], 1, 65001);
        rib_a.announce(p, e);
        let after = RibSnapshot::from_rib(&rib_a, Utc.timestamp_opt(2, 0).unwrap());

        let glue = GlueSet::builtin();
        let events = diff_snapshots(&before, &after, &org_map(), &glue, &DiffConfig::default());
        assert!(
            events.iter().any(|e| e.kind == MaEventKind::PrefixMove
                && e.asn_a == Some(65000)
                && e.asn_b == Some(65001)),
            "events={events:?}"
        );
    }

    #[test]
    fn detects_new_adj_and_footprint() {
        let glue = GlueSet::from_text("3356\n").unwrap();
        let map = org_map();
        let mut before = RibSnapshot {
            as_of: Utc.timestamp_opt(1, 0).unwrap(),
            ts_start: None,
            collector: None,
            source: None,
            prefixes: HashMap::new(),
        };
        before.prefixes.insert(
            "198.51.100.0/24".into(),
            PrefixObs {
                origin_asn: 65000,
                upstream_asn: Some(3356),
                as_path: vec![3356, 65000],
            },
        );

        let mut after = RibSnapshot {
            as_of: Utc.timestamp_opt(2, 0).unwrap(),
            ts_start: None,
            collector: None,
            source: None,
            prefixes: HashMap::new(),
        };
        // adjacency 65000-65001 appears
        after.prefixes.insert(
            "198.51.100.0/24".into(),
            PrefixObs {
                origin_asn: 65000,
                upstream_asn: Some(65001),
                as_path: vec![1, 65001, 65000],
            },
        );
        for i in 0..10 {
            after.prefixes.insert(
                format!("198.51.100.{i}/32"),
                PrefixObs {
                    origin_asn: 65000,
                    upstream_asn: Some(65001),
                    as_path: vec![65001, 65000],
                },
            );
        }

        let cfg = DiffConfig {
            heuristics: SubjectHeuristics::default(),
            footprint_rel_threshold: 0.2,
            footprint_abs_threshold: 5,
        };
        let events = diff_snapshots(&before, &after, &map, &glue, &cfg);
        assert!(events.iter().any(|e| e.kind == MaEventKind::NewAdj));
        assert!(events.iter().any(|e| e.kind == MaEventKind::FootprintStep));
        assert!(events.iter().any(|e| e.kind == MaEventKind::UpstreamConverge));
    }

    #[test]
    fn eval_case_hits_prefix_move() {
        let events = vec![MaEvent {
            kind: MaEventKind::PrefixMove,
            timestamp: Utc.timestamp_opt(100, 0).unwrap(),
            org_a: Some("a".into()),
            org_b: Some("b".into()),
            asn_a: Some(65000),
            asn_b: Some(65001),
            domains_a: vec![],
            domains_b: vec![],
            prefix: Some("203.0.113.0/24".into()),
            detail: "origin 65000 -> 65001".into(),
        }];
        let cases = vec![EvalCase {
            id: "t1".into(),
            expect_kind: MaEventKind::PrefixMove,
            asn_a: 65001,
            asn_b: Some(65000),
            prefix: Some("203.0.113.0/24".into()),
            window_start: Utc.timestamp_opt(50, 0).unwrap(),
            window_end: Utc.timestamp_opt(150, 0).unwrap(),
            expect_hit: true,
            notes: String::new(),
        }];
        let results = eval_cases(&cases, &events);
        assert_eq!(results.len(), 1);
        assert!(results[0].hit);
        assert!(results[0].passed);
    }
}
