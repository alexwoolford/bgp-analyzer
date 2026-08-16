//! RPKI Route Origin Validation (ROV).

use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

/// ROV validation outcome for a (prefix, origin ASN) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RpkiState {
    Valid,
    Invalid,
    #[default]
    Unknown,
}

impl std::fmt::Display for RpkiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpkiState::Valid => write!(f, "valid"),
            RpkiState::Invalid => write!(f, "invalid"),
            RpkiState::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Error)]
pub enum RpkiError {
    #[error("failed to open ROA source `{path}`: {source}")]
    Open {
        path: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("invalid ROA row: {0}")]
    InvalidRow(String),
}

/// A single Route Origin Authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roa {
    pub prefix: IpNet,
    pub max_length: u8,
    pub origin_asn: u32,
}

#[derive(Debug, Clone, Default)]
struct RoaSet {
    entries: Vec<Roa>,
}

/// Prefix trie of ROAs used for Route Origin Validation.
#[derive(Default)]
pub struct RoasTrie {
    trie: IpnetTrie<RoaSet>,
    count: usize,
}

impl RoasTrie {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn insert(&mut self, roa: Roa) {
        let prefix = roa.prefix;
        match self.trie.exact_match_mut(prefix) {
            Some(set) => {
                set.entries.push(roa);
            }
            None => {
                self.trie.insert(
                    prefix,
                    RoaSet {
                        entries: vec![roa],
                    },
                );
            }
        }
        self.count += 1;
    }

    /// Validate `prefix` announced by `origin_asn`.
    ///
    /// - **Valid**: covered by a ROA for this origin whose maxLength allows the prefix length.
    /// - **Invalid**: some covering ROA exists for the prefix (or a less-specific covering
    ///   announcement space) but none authorize this origin/length.
    /// - **Unknown**: no covering ROA exists.
    pub fn validate(&self, prefix: IpNet, origin_asn: u32) -> RpkiState {
        let mut saw_covering = false;

        // Walk covering prefixes from most specific match upward via LPM chain.
        for (net, set) in self.trie.matches(&prefix) {
            if !covers(net, prefix) {
                continue;
            }
            saw_covering = true;
            for roa in &set.entries {
                if roa.origin_asn == origin_asn
                    && prefix.prefix_len() >= roa.prefix.prefix_len()
                    && prefix.prefix_len() <= roa.max_length
                    && covers(roa.prefix, prefix)
                {
                    return RpkiState::Valid;
                }
            }
        }

        if saw_covering {
            RpkiState::Invalid
        } else {
            RpkiState::Unknown
        }
    }
}

fn covers(larger: IpNet, smaller: IpNet) -> bool {
    larger.prefix_len() <= smaller.prefix_len() && larger.contains(&smaller.network())
}

/// Load ROAs from a local path or HTTP(S) URL.
///
/// Accepts RIPE-style CSV dumps. Common header shapes:
/// - `URI,ASN,IP Prefix,Max Length,...`
/// - `asn,prefix,maxLength,...`
/// - headerless `asn,prefix,max_length`
pub fn load_roas(path_or_url: &str) -> Result<RoasTrie> {
    let reader = oneio::get_reader(path_or_url).map_err(|e| RpkiError::Open {
        path: path_or_url.to_string(),
        source: anyhow!(e),
    })?;

    let mut csv = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_reader(reader);

    let headers = csv
        .headers()
        .context("reading ROA CSV headers")?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();

    let (asn_idx, prefix_idx, maxlen_idx, headerless_first) =
        resolve_columns(&headers).context("resolving ROA CSV columns")?;

    let mut trie = RoasTrie::new();

    if headerless_first {
        // First row was misinterpreted as headers — parse it as data.
        if let Some(roa) = row_from_fields(
            &headers.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            0,
            1,
            2,
        )? {
            trie.insert(roa);
        }
    }

    for (line_no, record) in csv.records().enumerate() {
        let record = record.with_context(|| format!("ROA CSV record {}", line_no + 2))?;
        let fields: Vec<&str> = record.iter().collect();
        if let Some(roa) = row_from_fields(&fields, asn_idx, prefix_idx, maxlen_idx)
            .with_context(|| format!("ROA CSV record {}", line_no + 2))?
        {
            trie.insert(roa);
        }
    }

    info!(roas = trie.len(), source = path_or_url, "loaded ROAs");
    Ok(trie)
}

fn resolve_columns(headers: &[String]) -> Result<(usize, usize, usize, bool)> {
    let find = |candidates: &[&str]| {
        headers
            .iter()
            .position(|h| candidates.iter().any(|c| h == c || h.replace('_', " ") == *c))
    };

    if let (Some(a), Some(p), Some(m)) = (
        find(&["asn", "as", "origin", "origin asn", "origin_asn"]),
        find(&["ip prefix", "prefix", "ip_prefix", "ipprefix"]),
        find(&[
            "max length",
            "maxlen",
            "max_length",
            "maxlength",
            "max len",
        ]),
    ) {
        return Ok((a, p, m, false));
    }

    // Headerless: first "header" row looks like asn,prefix,maxlen
    if headers.len() >= 3
        && headers[0].parse::<u32>().is_ok()
        && IpNet::from_str(&headers[1]).is_ok()
    {
        return Ok((0, 1, 2, true));
    }

    Err(anyhow!(
        "could not find ASN/prefix/maxLength columns in {:?}",
        headers
    ))
}

fn row_from_fields(
    fields: &[&str],
    asn_idx: usize,
    prefix_idx: usize,
    maxlen_idx: usize,
) -> Result<Option<Roa>> {
    if fields.len() <= asn_idx.max(prefix_idx).max(maxlen_idx) {
        return Ok(None);
    }

    let asn_raw = fields[asn_idx].trim();
    if asn_raw.is_empty() || asn_raw.starts_with('#') {
        return Ok(None);
    }

    let origin_asn = parse_asn(asn_raw)
        .map_err(|e| RpkiError::InvalidRow(format!("ASN `{asn_raw}`: {e}")))?;
    let prefix = IpNet::from_str(fields[prefix_idx].trim())
        .map_err(|e| RpkiError::InvalidRow(format!("prefix: {e}")))?;
    let max_length: u8 = fields[maxlen_idx]
        .trim()
        .parse()
        .map_err(|e| RpkiError::InvalidRow(format!("maxLength: {e}")))?;

    Ok(Some(Roa {
        prefix,
        max_length,
        origin_asn,
    }))
}

fn parse_asn(raw: &str) -> Result<u32> {
    let s = raw
        .trim()
        .trim_start_matches("AS")
        .trim_start_matches("as");
    Ok(s.parse::<u32>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(prefix: &str) -> IpNet {
        prefix.parse().unwrap()
    }

    #[test]
    fn rov_valid_invalid_unknown() {
        let mut trie = RoasTrie::new();
        trie.insert(Roa {
            prefix: v4("1.0.0.0/16"),
            max_length: 24,
            origin_asn: 13335,
        });

        assert_eq!(
            trie.validate(v4("1.0.1.0/24"), 13335),
            RpkiState::Valid
        );
        assert_eq!(
            trie.validate(v4("1.0.1.0/24"), 64500),
            RpkiState::Invalid
        );
        assert_eq!(
            trie.validate(v4("1.0.1.0/25"), 13335),
            RpkiState::Invalid
        );
        assert_eq!(
            trie.validate(v4("8.8.8.0/24"), 15169),
            RpkiState::Unknown
        );
    }

    #[test]
    fn load_csv_with_headers() {
        // Real RPKI ROA rows excerpted from the 2022-01-01 public dump (not invented).
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/real-roas-excerpt-20220101.csv"
        );
        let trie = load_roas(path).unwrap();
        assert_eq!(trie.len(), 2);
        assert_eq!(
            trie.validate(v4("1.1.1.0/24"), 13335),
            RpkiState::Valid
        );
        assert_eq!(
            trie.validate(v4("1.1.1.0/24"), 64500),
            RpkiState::Invalid
        );
        assert_eq!(
            trie.validate(v4("8.8.8.0/24"), 15169),
            RpkiState::Valid
        );
    }
}
