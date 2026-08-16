//! Daily network-contact signal envelope + clean filters + rolling pair state.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::AsnPairFeature;
use bgp_map::OrgMap;

/// Marketplace / IP leasing ASNs that dominate dirty precision audits.
pub const DEFAULT_LEASING_ASNS: &[u32] = &[
    834, // IPXO
    396998, 211585, 49999, 61138, 43260,
];

/// Versioned BGP network-contact signal (ASN / org / domain attributes included).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignalEnvelope {
    pub schema_version: u32,
    pub source: String,
    /// Stable product kind for this feed.
    pub kind: String,
    pub as_of: DateTime<Utc>,
    pub prior_as_of: DateTime<Utc>,
    pub asn_a: u32,
    pub asn_b: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_a: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_b: Option<String>,
    #[serde(default)]
    pub domains_a: Vec<String>,
    #[serde(default)]
    pub domains_b: Vec<String>,
    pub prefixes_moved: u32,
    pub prefix_move_days: u32,
    pub new_adj_days: u32,
    pub upstream_converge_days: u32,
    pub persistence_days: i64,
    /// Triage heuristic only — not a calibrated deal probability.
    pub score: i64,
    #[serde(default)]
    pub event_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppress_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PairStateEntry {
    pub asn_lo: u32,
    pub asn_hi: u32,
    #[serde(default)]
    pub org_lo: Option<String>,
    #[serde(default)]
    pub org_hi: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub prefix_move_days: u32,
    pub prefixes_moved: u32,
    pub new_adj_days: u32,
    pub upstream_converge_days: u32,
    pub score: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PairStateStore {
    pub updated_at: Option<DateTime<Utc>>,
    pub pairs: HashMap<String, PairStateEntry>,
}

fn pair_key(lo: u32, hi: u32) -> String {
    format!("{lo}-{hi}")
}

impl PairStateStore {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading pair state {}", path.display()))?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let f = File::create(path)?;
        serde_json::to_writer_pretty(BufWriter::new(f), self)?;
        Ok(())
    }

    pub fn merge_day(
        &mut self,
        features: &[AsnPairFeature],
        as_of: DateTime<Utc>,
        retain_days: i64,
    ) {
        for f in features {
            let key = pair_key(f.asn_lo, f.asn_hi);
            let e = self.pairs.entry(key).or_insert_with(|| PairStateEntry {
                asn_lo: f.asn_lo,
                asn_hi: f.asn_hi,
                org_lo: f.org_lo.clone(),
                org_hi: f.org_hi.clone(),
                first_seen: f.first_seen,
                last_seen: f.last_seen,
                prefix_move_days: 0,
                prefixes_moved: 0,
                new_adj_days: 0,
                upstream_converge_days: 0,
                score: 0,
            });
            if f.first_seen < e.first_seen {
                e.first_seen = f.first_seen;
            }
            if f.last_seen > e.last_seen {
                e.last_seen = f.last_seen;
            }
            e.prefix_move_days = e.prefix_move_days.saturating_add(f.prefix_move_days);
            e.prefixes_moved = e.prefixes_moved.saturating_add(f.prefixes_moved);
            e.new_adj_days = e.new_adj_days.saturating_add(f.new_adj_days);
            e.upstream_converge_days = e
                .upstream_converge_days
                .saturating_add(f.upstream_converge_days);
            e.score = e.score.max(f.score);
            if e.org_lo.is_none() {
                e.org_lo = f.org_lo.clone();
            }
            if e.org_hi.is_none() {
                e.org_hi = f.org_hi.clone();
            }
        }
        let cutoff = as_of - Duration::days(retain_days);
        self.pairs.retain(|_, e| e.last_seen >= cutoff);
        self.updated_at = Some(as_of);
    }

    pub fn get(&self, lo: u32, hi: u32) -> Option<&PairStateEntry> {
        self.pairs.get(&pair_key(lo, hi))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanDropReason {
    SameOrg,
    Leasing,
}

pub fn leasing_set(extra: &[u32]) -> HashSet<u32> {
    let mut s: HashSet<u32> = DEFAULT_LEASING_ASNS.iter().copied().collect();
    s.extend(extra.iter().copied());
    s
}

pub fn clean_drop_reason(
    lo: u32,
    hi: u32,
    org_lo: Option<&str>,
    org_hi: Option<&str>,
    leasing: &HashSet<u32>,
) -> Option<CleanDropReason> {
    if leasing.contains(&lo) || leasing.contains(&hi) {
        return Some(CleanDropReason::Leasing);
    }
    if let (Some(a), Some(b)) = (org_lo, org_hi) {
        if !a.is_empty() && a == b {
            return Some(CleanDropReason::SameOrg);
        }
    }
    None
}

pub fn filter_clean_features(
    features: &[AsnPairFeature],
    leasing: &HashSet<u32>,
) -> (Vec<AsnPairFeature>, Vec<(AsnPairFeature, CleanDropReason)>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for f in features {
        match clean_drop_reason(
            f.asn_lo,
            f.asn_hi,
            f.org_lo.as_deref(),
            f.org_hi.as_deref(),
            leasing,
        ) {
            Some(r) => dropped.push((f.clone(), r)),
            None => kept.push(f.clone()),
        }
    }
    (kept, dropped)
}

fn event_kinds_from_feature(f: &AsnPairFeature) -> Vec<String> {
    let mut k = Vec::new();
    if f.prefix_move_days > 0 {
        k.push("prefix_move".into());
    }
    if f.new_adj_days > 0 {
        k.push("new_adj".into());
    }
    if f.upstream_converge_days > 0 {
        k.push("upstream_converge".into());
    }
    k
}

fn domains_for(org_map: &OrgMap, asn: u32) -> Vec<String> {
    org_map
        .org_for_asn(asn)
        .map(|o| o.domains.clone())
        .unwrap_or_default()
}

/// Build network-contact signals from cleaned features + optional rolling state.
pub fn build_signals(
    features: &[AsnPairFeature],
    org_map: &OrgMap,
    as_of: DateTime<Utc>,
    prior_as_of: DateTime<Utc>,
    state: Option<&PairStateStore>,
) -> Vec<SignalEnvelope> {
    let mut out = Vec::with_capacity(features.len());
    for f in features {
        let st = state.and_then(|s| s.get(f.asn_lo, f.asn_hi));
        let persistence_days = st
            .map(|e| (e.last_seen - e.first_seen).num_days())
            .unwrap_or(f.persistence_days);
        let prefixes_moved = st
            .map(|e| e.prefixes_moved.max(f.prefixes_moved))
            .unwrap_or(f.prefixes_moved);
        let score = st.map(|e| e.score.max(f.score)).unwrap_or(f.score);
        let prefix_move_days = st
            .map(|e| e.prefix_move_days.max(f.prefix_move_days))
            .unwrap_or(f.prefix_move_days);
        let new_adj_days = st
            .map(|e| e.new_adj_days.max(f.new_adj_days))
            .unwrap_or(f.new_adj_days);
        let upstream_converge_days = st
            .map(|e| e.upstream_converge_days.max(f.upstream_converge_days))
            .unwrap_or(f.upstream_converge_days);

        out.push(SignalEnvelope {
            schema_version: 1,
            source: "bgp_analyzer".into(),
            kind: "network_contact".into(),
            as_of,
            prior_as_of,
            asn_a: f.asn_lo,
            asn_b: f.asn_hi,
            org_a: f.org_lo.clone(),
            org_b: f.org_hi.clone(),
            domains_a: domains_for(org_map, f.asn_lo),
            domains_b: domains_for(org_map, f.asn_hi),
            prefixes_moved,
            prefix_move_days,
            new_adj_days,
            upstream_converge_days,
            persistence_days,
            score,
            event_kinds: event_kinds_from_feature(f),
            suppress_flags: vec![],
        });
    }
    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.asn_a.cmp(&b.asn_a)));
    out
}

pub fn write_signals_jsonl(path: impl AsRef<Path>, signals: &[SignalEnvelope]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = BufWriter::new(f);
    for s in signals {
        serde_json::to_writer(&mut w, s)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

pub fn append_inbox_jsonl(path: impl AsRef<Path>, signals: &[SignalEnvelope]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening inbox {}", path.display()))?;
    let mut w = BufWriter::new(f);
    for s in signals {
        serde_json::to_writer(&mut w, s)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn drops_same_org_and_leasing() {
        let leasing = leasing_set(&[]);
        assert_eq!(
            clean_drop_reason(1, 2, Some("org:a"), Some("org:a"), &leasing),
            Some(CleanDropReason::SameOrg)
        );
        assert_eq!(
            clean_drop_reason(834, 100, Some("x"), Some("y"), &leasing),
            Some(CleanDropReason::Leasing)
        );
        assert_eq!(
            clean_drop_reason(1, 2, Some("org:a"), Some("org:b"), &leasing),
            None
        );
    }

    #[test]
    fn signal_envelope_schema_fields() {
        let env = SignalEnvelope {
            schema_version: 1,
            source: "bgp_analyzer".into(),
            kind: "network_contact".into(),
            as_of: Utc.with_ymd_and_hms(2026, 8, 14, 0, 30, 0).unwrap(),
            prior_as_of: Utc.with_ymd_and_hms(2026, 8, 13, 0, 30, 0).unwrap(),
            asn_a: 1,
            asn_b: 2,
            org_a: None,
            org_b: None,
            domains_a: vec![],
            domains_b: vec![],
            prefixes_moved: 2,
            prefix_move_days: 1,
            new_adj_days: 0,
            upstream_converge_days: 0,
            persistence_days: 0,
            score: 5,
            event_kinds: vec!["prefix_move".into()],
            suppress_flags: vec![],
        };
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["source"], "bgp_analyzer");
        assert_eq!(v["kind"], "network_contact");
        assert_eq!(v["schema_version"], 1);
        assert!(v.get("tile").is_none());
        assert!(v.get("corroboration_only").is_none());
    }

    #[test]
    fn pair_state_merges_and_prunes() {
        let ts = Utc.with_ymd_and_hms(2022, 1, 10, 0, 30, 0).unwrap();
        let f = AsnPairFeature {
            asn_lo: 1,
            asn_hi: 2,
            org_lo: Some("a".into()),
            org_hi: Some("b".into()),
            prefix_move_days: 1,
            prefixes_moved: 3,
            new_adj_days: 0,
            upstream_converge_days: 0,
            first_seen: ts,
            last_seen: ts,
            persistence_days: 0,
            score: 10,
        };
        let mut st = PairStateStore::default();
        st.merge_day(&[f], ts, 30);
        assert!(st.get(1, 2).is_some());
        let old = ts - Duration::days(60);
        st.pairs.get_mut(&pair_key(1, 2)).unwrap().last_seen = old;
        st.merge_day(&[], ts, 30);
        assert!(st.get(1, 2).is_none());
    }
}
