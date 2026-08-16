//! Valley-free path validation and alert records.

use std::io::Read;

use anyhow::{Context, Result};
use bgp_rpki::RpkiState;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;
use valley_free::{RelType, Topology, TopologyExt};

#[derive(Debug, Error)]
pub enum DetectError {
    #[error("failed to load AS relationship file `{path}`: {source}")]
    Load {
        path: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("failed to parse AS relationship topology: {0}")]
    Parse(String),
}

/// Outcome of valley-free checking for an AS_PATH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathVerdict {
    /// Path obeys valley-free commercial relationships.
    ValleyFree,
    /// Path contains an explicit valley / leak pattern.
    LeakSuspected,
    /// One or more AS adjacencies are missing from the relationship graph.
    Incomplete,
    /// Path too short to evaluate.
    TooShort,
}

/// Alert emitted when ROV is invalid and/or a route leak is suspected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub timestamp: DateTime<Utc>,
    pub prefix: String,
    pub origin_asn: Option<u32>,
    pub as_path: Vec<u32>,
    pub peer_asn: u32,
    pub collector: Option<String>,
    pub rpki_state: RpkiState,
    pub path_verdict: PathVerdict,
    pub leak_suspected: bool,
    pub reason: String,
}

impl Alert {
    pub fn should_emit(&self) -> bool {
        self.rpki_state == RpkiState::Invalid || self.leak_suspected
    }
}

/// AS-relationship topology used for valley-free checks.
#[derive(Debug, Clone)]
pub struct LeakDetector {
    topology: Topology,
}

impl LeakDetector {
    pub fn from_topology(topology: Topology) -> Self {
        Self { topology }
    }

    pub fn from_edges(edges: Vec<(u32, u32, RelType)>) -> Self {
        Self {
            topology: Topology::from_edges(edges),
        }
    }

    /// Load CAIDA serial-1 AS-relationship data from a path or URL (supports `.bz2`).
    pub fn from_caida_path(path_or_url: &str) -> Result<Self> {
        let mut reader = oneio::get_reader(path_or_url).map_err(|e| DetectError::Load {
            path: path_or_url.to_string(),
            source: e.into(),
        })?;
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading AS-rel from {path_or_url}"))?;
        let topology = Topology::from_caida(bytes.as_slice())
            .map_err(|e| DetectError::Parse(format!("{e:?}")))?;
        info!(source = path_or_url, "loaded CAIDA AS relationships");
        Ok(Self { topology })
    }

    /// Check an AS_PATH as encoded in BGP (left = neighbor, right = origin).
    pub fn check_as_path(&self, as_path: &[u32]) -> PathVerdict {
        if as_path.len() < 2 {
            return PathVerdict::TooShort;
        }

        // Propagation direction is origin → neighbor (reverse of wire AS_PATH).
        let mut path: Vec<u32> = as_path.to_vec();
        path.reverse();
        // Collapse AS prepending.
        path.dedup();
        if path.len() < 2 {
            return PathVerdict::TooShort;
        }

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Phase {
            Up,
            Peer,
            Down,
        }

        let mut phase = Phase::Up;
        let mut incomplete = false;

        for w in path.windows(2) {
            let from = w[0];
            let to = w[1];
            let rel = relationship(&self.topology, from, to);
            let Some(rel) = rel else {
                incomplete = true;
                continue;
            };

            match (phase, rel) {
                // Still climbing toward providers.
                (Phase::Up, RelType::CustomerToProvider) => {}
                (Phase::Up, RelType::PeerToPeer) => phase = Phase::Peer,
                (Phase::Up, RelType::ProviderToCustomer) => phase = Phase::Down,

                // After a peer hop, only downhill is allowed.
                (Phase::Peer, RelType::ProviderToCustomer) => phase = Phase::Down,
                (Phase::Peer, RelType::PeerToPeer | RelType::CustomerToProvider) => {
                    return PathVerdict::LeakSuspected;
                }

                // Downhill only.
                (Phase::Down, RelType::ProviderToCustomer) => {}
                (Phase::Down, RelType::PeerToPeer | RelType::CustomerToProvider) => {
                    return PathVerdict::LeakSuspected;
                }
            }
        }

        if incomplete {
            PathVerdict::Incomplete
        } else {
            PathVerdict::ValleyFree
        }
    }
}

fn relationship(topo: &Topology, from: u32, to: u32) -> Option<RelType> {
    if topo
        .providers_of(from)
        .map(|s| s.contains(&to))
        .unwrap_or(false)
    {
        return Some(RelType::CustomerToProvider);
    }
    if topo
        .customers_of(from)
        .map(|s| s.contains(&to))
        .unwrap_or(false)
    {
        return Some(RelType::ProviderToCustomer);
    }
    if topo
        .peers_of(from)
        .map(|s| s.contains(&to))
        .unwrap_or(false)
    {
        return Some(RelType::PeerToPeer);
    }
    None
}

/// Build an alert if ROV invalid or leak suspected.
pub fn maybe_alert(
    timestamp: DateTime<Utc>,
    prefix: IpNet,
    origin_asn: Option<u32>,
    as_path: Vec<u32>,
    peer_asn: u32,
    collector: Option<String>,
    rpki_state: RpkiState,
    path_verdict: PathVerdict,
) -> Option<Alert> {
    let leak_suspected = path_verdict == PathVerdict::LeakSuspected;
    let mut reasons = Vec::new();
    if rpki_state == RpkiState::Invalid {
        reasons.push("rpki_invalid".to_string());
    }
    if leak_suspected {
        reasons.push("valley_free_violation".to_string());
    }
    if reasons.is_empty() {
        return None;
    }
    Some(Alert {
        timestamp,
        prefix: prefix.to_string(),
        origin_asn,
        as_path,
        peer_asn,
        collector,
        rpki_state,
        path_verdict,
        leak_suspected,
        reason: reasons.join(","),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use valley_free::RelType;

    fn diamond() -> LeakDetector {
        // 1 is provider of 2 and 3; 2 and 3 peer; both provide 4.
        LeakDetector::from_edges(vec![
            (1, 2, RelType::ProviderToCustomer),
            (1, 3, RelType::ProviderToCustomer),
            (2, 3, RelType::PeerToPeer),
            (2, 4, RelType::ProviderToCustomer),
            (3, 4, RelType::ProviderToCustomer),
        ])
    }

    #[test]
    fn valley_free_customer_path_ok() {
        let det = diamond();
        // Wire AS_PATH neighbor→origin: 2 1  means propagation 1→2? Wait.
        // Origin 4, via 2, observed at 1's customer side: path [2, 4] means neighbor 2 origin 4.
        // Propagation 4→2. 2 is provider of 4 → P2C from 4 to 2? from=4 to=2: 2 is provider of 4 → C2P.
        assert_eq!(det.check_as_path(&[2, 4]), PathVerdict::ValleyFree);
        // 1 2 4: neighbor 1, then 2, origin 4. Propagation 4→2→1.
        assert_eq!(det.check_as_path(&[1, 2, 4]), PathVerdict::ValleyFree);
    }

    #[test]
    fn detects_provider_to_provider_leak() {
        let det = LeakDetector::from_edges(vec![
            (100, 200, RelType::ProviderToCustomer), // 100 provides 200
            (300, 200, RelType::ProviderToCustomer), // 300 provides 200
            (100, 400, RelType::ProviderToCustomer),
            (300, 500, RelType::ProviderToCustomer),
        ]);
        // Leak: route from customer 200 learned from provider 100 and re-announced
        // toward provider 300. Wire path observed by 300: [200, 100, ...]
        // Simpler classic leak path: 300 ← 200 ← 100 where 200 is customer of both.
        // Propagation origin 400 → 100 → 200 → 300. Relationships:
        // 400→100: C2P (100 provider of 400)
        // 100→200: P2C (100 provider of 200)
        // 200→300: C2P (300 provider of 200)  ← valley after down
        // Wire AS_PATH: [300, 200, 100, 400]
        let verdict = det.check_as_path(&[300, 200, 100, 400]);
        assert_eq!(verdict, PathVerdict::LeakSuspected);
    }

    #[test]
    fn alert_only_on_invalid_or_leak() {
        let a = maybe_alert(
            Utc::now(),
            "1.2.3.0/24".parse().unwrap(),
            Some(1),
            vec![1, 2],
            9,
            None,
            RpkiState::Valid,
            PathVerdict::ValleyFree,
        );
        assert!(a.is_none());

        let b = maybe_alert(
            Utc::now(),
            "1.2.3.0/24".parse().unwrap(),
            Some(1),
            vec![1, 2],
            9,
            None,
            RpkiState::Invalid,
            PathVerdict::ValleyFree,
        )
        .unwrap();
        assert!(b.should_emit());
    }
}
