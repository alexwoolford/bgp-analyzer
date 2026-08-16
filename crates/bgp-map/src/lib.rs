//! ASN ↔ organization ↔ eTLD+1 spine and glue suppression for BGP network-contact signals.
//!
//! Mapping is **many-to-many**: one org may own many ASNs and many domains; a domain
//! is an attribute for downstream use (optional), never a 1:1 identity with an ASN.
//!
//! Product maps must come from **real** sources (PeeringDB / CAIDA / optional domain watchlists).
//! See [`crate::peeringdb`] and `docs/REAL_DATA.md`.

mod peeringdb;

pub use peeringdb::{build_org_map_from_peeringdb, write_org_map_json, PeeringDbBuildOptions};

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

/// Default mid-market ceiling: ASNs announcing more than this many prefixes are
/// treated as too large to be M&A *subjects* (still usable as glue/context).
pub const DEFAULT_MAX_PREFIXES_FOR_SUBJECT: u32 = 5_000;

/// Minimum ASNs / footprint to bother watching (filters empty stubs).
pub const DEFAULT_MIN_PREFIXES_FOR_SUBJECT: u32 = 1;

#[derive(Debug, Error)]
pub enum MapError {
    #[error("failed to read `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse org map JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid ASN `{0}`")]
    InvalidAsn(String),
}

/// Heuristics for whether an ASN may be an M&A watchlist *subject*.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SubjectHeuristics {
    /// Exclude ASNs on the glue suppress list.
    pub exclude_glue: bool,
    /// When prefix counts are known, require `<= max_prefixes`.
    pub max_prefixes: Option<u32>,
    /// When prefix counts are known, require `>= min_prefixes`.
    pub min_prefixes: Option<u32>,
}

impl Default for SubjectHeuristics {
    fn default() -> Self {
        Self {
            exclude_glue: true,
            max_prefixes: Some(DEFAULT_MAX_PREFIXES_FOR_SUBJECT),
            min_prefixes: Some(DEFAULT_MIN_PREFIXES_FOR_SUBJECT),
        }
    }
}

impl SubjectHeuristics {
    /// Return true if this ASN is eligible as a network-contact subject.
    pub fn is_subject(&self, asn: u32, glue: &GlueSet, prefix_count: Option<u32>) -> bool {
        if self.exclude_glue && glue.contains(asn) {
            return false;
        }
        if let Some(count) = prefix_count {
            if let Some(max) = self.max_prefixes {
                if count > max {
                    return false;
                }
            }
            if let Some(min) = self.min_prefixes {
                if count < min {
                    return false;
                }
            }
        }
        true
    }
}

/// Set of ASNs treated as transit / hyperscaler / CDN glue.
#[derive(Debug, Clone, Default)]
pub struct GlueSet {
    asns: HashSet<u32>,
}

impl GlueSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.asns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.asns.is_empty()
    }

    pub fn contains(&self, asn: u32) -> bool {
        self.asns.contains(&asn)
    }

    pub fn insert(&mut self, asn: u32) {
        self.asns.insert(asn);
    }

    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.asns.iter().copied()
    }

    /// Load glue ASNs from a text file (one ASN per line, `#` comments).
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| MapError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_text(&text)
    }

    pub fn from_text(text: &str) -> Result<Self> {
        let mut set = GlueSet::new();
        for (lineno, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let asn: u32 = line
                .parse()
                .map_err(|_| MapError::InvalidAsn(format!("line {}: `{line}`", lineno + 1)))?;
            set.insert(asn);
        }
        info!(glue_asns = set.len(), "loaded glue ASN suppress list");
        Ok(set)
    }

    /// Built-in starter list (hyperscalers + selected Tier-1 / CDN). Prefer
    /// [`from_file`] with [`fixtures/glue-asns.txt`](../../fixtures/glue-asns.txt) in prod.
    pub fn builtin() -> Self {
        const BUILTIN: &[u32] = &[
            16509, 14618, 15169, 36040, 396982, 8075, 13335, 20940, 54113, 16625, 174, 209, 286,
            701, 1239, 1299, 2914, 3257, 3320, 3356, 3491, 6453, 6461, 6762, 6830, 7018, 3561,
            7922, 714, 32934, 13414, 2906,
        ];
        let mut set = GlueSet::new();
        for &asn in BUILTIN {
            set.insert(asn);
        }
        set
    }
}

/// Stable organization identifier for ASN↔org attribution.
pub type OrgId = String;

/// One organization with many ASNs and many eTLD+1 domains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgRecord {
    pub org_id: OrgId,
    pub name: String,
    /// Autonomous system numbers attributed to this org.
    pub asns: Vec<u32>,
    /// Registered domains (eTLD+1 preferred) for optional downstream use.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Optional known prefix footprint (for subject heuristics).
    #[serde(default)]
    pub prefix_count_hint: Option<u32>,
    /// Optional ticker / LEI / external id (opaque string).
    #[serde(default)]
    pub external_id: Option<String>,
}

/// Many-to-many ASN ↔ org ↔ domain index.
#[derive(Debug, Clone, Default)]
pub struct OrgMap {
    orgs: HashMap<OrgId, OrgRecord>,
    asn_to_orgs: HashMap<u32, Vec<OrgId>>,
    domain_to_orgs: HashMap<String, Vec<OrgId>>,
}

impl OrgMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.orgs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.orgs.is_empty()
    }

    pub fn orgs(&self) -> impl Iterator<Item = &OrgRecord> {
        self.orgs.values()
    }

    pub fn get(&self, org_id: &str) -> Option<&OrgRecord> {
        self.orgs.get(org_id)
    }

    pub fn insert(&mut self, mut record: OrgRecord) {
        record.asns.sort_unstable();
        record.asns.dedup();
        record.domains = record
            .domains
            .into_iter()
            .map(|d| normalize_domain(&d))
            .filter(|d| !d.is_empty())
            .collect();
        record.domains.sort();
        record.domains.dedup();

        let org_id = record.org_id.clone();
        for &asn in &record.asns {
            self.asn_to_orgs
                .entry(asn)
                .or_default()
                .push(org_id.clone());
        }
        for domain in &record.domains {
            self.domain_to_orgs
                .entry(domain.clone())
                .or_default()
                .push(org_id.clone());
        }
        self.orgs.insert(org_id, record);
    }

    /// Primary org for an ASN (first registration wins if multi-mapped).
    pub fn org_for_asn(&self, asn: u32) -> Option<&OrgRecord> {
        self.asn_to_orgs
            .get(&asn)
            .and_then(|ids| ids.first())
            .and_then(|id| self.orgs.get(id))
    }

    pub fn orgs_for_asn(&self, asn: u32) -> Vec<&OrgRecord> {
        self.asn_to_orgs
            .get(&asn)
            .map(|ids| ids.iter().filter_map(|id| self.orgs.get(id)).collect())
            .unwrap_or_default()
    }

    pub fn orgs_for_domain(&self, domain: &str) -> Vec<&OrgRecord> {
        let d = normalize_domain(domain);
        self.domain_to_orgs
            .get(&d)
            .map(|ids| ids.iter().filter_map(|id| self.orgs.get(id)).collect())
            .unwrap_or_default()
    }

    /// Watchlist ASNs that pass subject heuristics given glue + optional prefix hints.
    pub fn subject_asns(&self, glue: &GlueSet, heuristics: &SubjectHeuristics) -> HashSet<u32> {
        let mut out = HashSet::new();
        for org in self.orgs.values() {
            let hint = org.prefix_count_hint;
            for &asn in &org.asns {
                if heuristics.is_subject(asn, glue, hint) {
                    out.insert(asn);
                }
            }
        }
        out
    }

    /// Load from JSON: `{ "orgs": [ OrgRecord, ... ] }` or a bare array of OrgRecord.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| MapError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_json_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn from_json_str(text: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            source: Option<String>,
            #[serde(default)]
            built_at: Option<String>,
            orgs: Vec<OrgRecord>,
        }

        let records: Vec<OrgRecord> = if let Ok(w) = serde_json::from_str::<Wrapper>(text) {
            let _ = (w.source, w.built_at);
            w.orgs
        } else {
            serde_json::from_str(text)?
        };

        let mut map = OrgMap::new();
        for rec in records {
            map.insert(rec);
        }
        info!(orgs = map.len(), "loaded org map");
        Ok(map)
    }

    /// Enrich domains from an optional watchlist file (one domain per line).
    /// Domains are attached to orgs whose `name` or existing domain shares a label,
    /// or whose `org_id` equals the domain — conservative; unmatched lines are skipped.
    pub fn enrich_domains_from_watchlist(&mut self, path: impl AsRef<Path>) -> Result<usize> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| MapError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let mut added = 0usize;
        for line in text.lines() {
            let domain = normalize_domain(line);
            if domain.is_empty() || domain.starts_with('#') {
                continue;
            }
            // Exact org_id match or existing domain already present → skip enrich noise.
            if self.orgs.contains_key(&domain) {
                if let Some(org) = self.orgs.get_mut(&domain) {
                    if !org.domains.iter().any(|d| d == &domain) {
                        org.domains.push(domain.clone());
                        self.domain_to_orgs
                            .entry(domain.clone())
                            .or_default()
                            .push(org.org_id.clone());
                        added += 1;
                    }
                }
                continue;
            }
            // Match when domain equals an existing domain on some org (no-op) or
            // when the registrable label appears in org_id.
            let label = domain.split('.').next().unwrap_or("");
            if label.is_empty() {
                continue;
            }
            let targets: Vec<OrgId> = self
                .orgs
                .values()
                .filter(|o| {
                    o.org_id.contains(label)
                        || o.name.to_ascii_lowercase().contains(label)
                        || o.domains.iter().any(|d| d.contains(label))
                })
                .map(|o| o.org_id.clone())
                .collect();
            for org_id in targets {
                if let Some(org) = self.orgs.get_mut(&org_id) {
                    if !org.domains.iter().any(|d| d == &domain) {
                        org.domains.push(domain.clone());
                        self.domain_to_orgs
                            .entry(domain.clone())
                            .or_default()
                            .push(org_id.clone());
                        added += 1;
                    }
                }
            }
        }
        info!(added, "enriched org domains from domain watchlist");
        Ok(added)
    }
}

pub(crate) fn normalize_domain(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glue_from_text_and_subject_heuristics() {
        let glue = GlueSet::from_text("16509\n# comment\n3356\n").unwrap();
        assert!(glue.contains(16509));
        assert!(glue.contains(3356));
        let h = SubjectHeuristics::default();
        assert!(!h.is_subject(16509, &glue, Some(10)));
        assert!(h.is_subject(65000, &glue, Some(10)));
        assert!(!h.is_subject(65000, &glue, Some(50_000)));
    }

    #[test]
    fn org_map_many_to_many() {
        let mut map = OrgMap::new();
        map.insert(OrgRecord {
            org_id: "acme".into(),
            name: "Acme Corp".into(),
            asns: vec![65000, 65001],
            domains: vec!["acme.com".into(), "acme.co.uk".into()],
            prefix_count_hint: Some(12),
            external_id: None,
        });
        map.insert(OrgRecord {
            org_id: "beta".into(),
            name: "Beta Inc".into(),
            asns: vec![65002],
            domains: vec!["beta.io".into()],
            prefix_count_hint: Some(3),
            external_id: Some("TICKER:BETA".into()),
        });

        assert_eq!(map.org_for_asn(65000).unwrap().org_id, "acme");
        assert_eq!(map.orgs_for_domain("acme.com").len(), 1);
        let glue = GlueSet::builtin();
        let subjects = map.subject_asns(&glue, &SubjectHeuristics::default());
        assert!(subjects.contains(&65000));
        assert!(subjects.contains(&65002));
    }

    #[test]
    fn load_json_wrapper() {
        let json = r#"{
          "orgs": [
            {
              "org_id": "acme",
              "name": "Acme",
              "asns": [65000],
              "domains": ["acme.com"]
            }
          ]
        }"#;
        let map = OrgMap::from_json_str(json).unwrap();
        assert_eq!(map.len(), 1);
    }
}
