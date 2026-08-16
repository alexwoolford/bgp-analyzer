//! Mutable RIB with attribute interning.

use std::collections::HashMap;

use indexmap::IndexSet;
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use serde::{Deserialize, Serialize};

pub use bgp_rpki::RpkiState;

/// Interned identifier for a deduplicated attribute (AS_PATH or communities).
pub type AttrId = u32;

/// Deduplicates repeated AS_PATH / community vectors into compact numeric IDs.
#[derive(Debug, Default)]
pub struct AttributeInterner {
    as_paths: IndexSet<Vec<u32>>,
    communities: IndexSet<Vec<u32>>,
}

impl AttributeInterner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn intern_as_path(&mut self, path: &[u32]) -> AttrId {
        intern(&mut self.as_paths, path)
    }

    pub fn intern_communities(&mut self, communities: &[u32]) -> AttrId {
        intern(&mut self.communities, communities)
    }

    pub fn as_path(&self, id: AttrId) -> Option<&[u32]> {
        self.as_paths.get_index(id as usize).map(|v| v.as_slice())
    }

    pub fn communities(&self, id: AttrId) -> Option<&[u32]> {
        self.communities
            .get_index(id as usize)
            .map(|v| v.as_slice())
    }

    pub fn as_path_count(&self) -> usize {
        self.as_paths.len()
    }

    pub fn community_count(&self) -> usize {
        self.communities.len()
    }
}

fn intern(set: &mut IndexSet<Vec<u32>>, values: &[u32]) -> AttrId {
    if let Some(idx) = set.get_index_of(values) {
        return idx as AttrId;
    }
    let (idx, _) = set.insert_full(values.to_vec());
    idx as AttrId
}

/// Per-prefix route attributes stored in the RIB.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteEntry {
    pub origin_asn: Option<u32>,
    pub as_path_id: AttrId,
    pub peer_asn: u32,
    pub communities_id: Option<AttrId>,
    pub rpki: RpkiState,
    pub timestamp: f64,
}

/// In-memory Routing Information Base keyed by IP prefix.
///
/// Routes are stored per (prefix, peer_asn) so multi-peer collector views do not
/// clobber each other. Longest-prefix match returns an arbitrary best peer entry
/// for the most specific prefix.
#[derive(Default)]
pub struct Rib {
    trie: IpnetTrie<HashMap<u32, RouteEntry>>,
    prefix_count: usize,
    route_count: usize,
    pub interner: AttributeInterner,
}

impl Rib {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn prefix_count(&self) -> usize {
        self.prefix_count
    }

    pub fn route_count(&self) -> usize {
        self.route_count
    }

    pub fn announce(&mut self, prefix: IpNet, entry: RouteEntry) {
        let peer = entry.peer_asn;
        match self.trie.exact_match_mut(prefix) {
            Some(peers) => {
                if peers.insert(peer, entry).is_none() {
                    self.route_count += 1;
                }
            }
            None => {
                let mut peers = HashMap::new();
                peers.insert(peer, entry);
                self.trie.insert(prefix, peers);
                self.prefix_count += 1;
                self.route_count += 1;
            }
        }
    }

    pub fn withdraw(&mut self, prefix: IpNet, peer_asn: u32) -> bool {
        let Some(peers) = self.trie.exact_match_mut(prefix) else {
            return false;
        };
        if peers.remove(&peer_asn).is_some() {
            self.route_count = self.route_count.saturating_sub(1);
            if peers.is_empty() {
                self.trie.remove(prefix);
                self.prefix_count = self.prefix_count.saturating_sub(1);
            }
            true
        } else {
            false
        }
    }

    pub fn exact_match(&self, prefix: IpNet) -> Option<&HashMap<u32, RouteEntry>> {
        self.trie.exact_match(prefix)
    }

    pub fn longest_match(
        &self,
        addr: std::net::IpAddr,
    ) -> Option<(IpNet, &HashMap<u32, RouteEntry>)> {
        let host = IpNet::from(addr);
        self.trie.longest_match(&host)
    }

    /// Iterate all (prefix, peer_asn → entry) currently in the RIB.
    pub fn iter(&self) -> impl Iterator<Item = (IpNet, &HashMap<u32, RouteEntry>)> + '_ {
        self.trie.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interner_dedupes_paths() {
        let mut interner = AttributeInterner::new();
        let a = interner.intern_as_path(&[1, 2, 3]);
        let b = interner.intern_as_path(&[1, 2, 3]);
        let c = interner.intern_as_path(&[1, 2, 4]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(interner.as_path_count(), 2);
        assert_eq!(interner.as_path(a).unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn announce_withdraw_and_lpm() {
        let mut rib = Rib::new();
        let p24: IpNet = "10.0.1.0/24".parse().unwrap();
        let p16: IpNet = "10.0.0.0/16".parse().unwrap();

        let path_id = rib.interner.intern_as_path(&[65000, 65001]);
        rib.announce(
            p16,
            RouteEntry {
                origin_asn: Some(65001),
                as_path_id: path_id,
                peer_asn: 1,
                communities_id: None,
                rpki: RpkiState::Unknown,
                timestamp: 1.0,
            },
        );
        rib.announce(
            p24,
            RouteEntry {
                origin_asn: Some(65001),
                as_path_id: path_id,
                peer_asn: 1,
                communities_id: None,
                rpki: RpkiState::Valid,
                timestamp: 2.0,
            },
        );

        assert_eq!(rib.prefix_count(), 2);
        assert_eq!(rib.route_count(), 2);

        let addr: std::net::IpAddr = "10.0.1.5".parse().unwrap();
        let (matched, peers) = rib.longest_match(addr).unwrap();
        assert_eq!(matched, p24);
        assert_eq!(peers.get(&1).unwrap().rpki, RpkiState::Valid);

        assert!(rib.withdraw(p24, 1));
        assert_eq!(rib.prefix_count(), 1);
        let (matched, _) = rib.longest_match(addr).unwrap();
        assert_eq!(matched, p16);
    }
}
