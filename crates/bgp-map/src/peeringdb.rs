//! Build [`OrgMap`] from the live PeeringDB API (real network operator registrations).

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tracing::{info, warn};

use crate::{normalize_domain, GlueSet, OrgMap, OrgRecord, SubjectHeuristics};

const PEERINGDB_NET: &str = "https://www.peeringdb.com/api/net";
const PEERINGDB_ORG: &str = "https://www.peeringdb.com/api/org";
const PAGE: usize = 250;
/// Polite delay between successful page fetches.
const PAGE_DELAY: Duration = Duration::from_millis(400);
const MAX_RETRIES: u32 = 12;

#[derive(Debug, Deserialize)]
struct PdbList<T> {
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct PdbNet {
    org_id: u64,
    asn: u32,
    #[serde(default)]
    website: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PdbOrg {
    id: u64,
    name: String,
    #[serde(default)]
    website: Option<String>,
}

/// Options for constructing a mid-market org map from PeeringDB.
#[derive(Debug, Clone)]
pub struct PeeringDbBuildOptions {
    pub heuristics: SubjectHeuristics,
    /// Max API pages of `/net` to fetch (each page = [`PAGE`] records). `None` = all.
    pub max_net_pages: Option<usize>,
    pub user_agent: String,
}

impl Default for PeeringDbBuildOptions {
    fn default() -> Self {
        Self {
            heuristics: SubjectHeuristics::default(),
            max_net_pages: None,
            user_agent: "bgp-analyzer/0.1 (research; real-data org-map builder)".into(),
        }
    }
}

/// Fetch PeeringDB nets + orgs and build a many-to-many [`OrgMap`].
///
/// Glue ASNs are excluded as subjects. Domains come from PeeringDB `website` fields
/// (org + net), normalized to hostnames — never invented.
pub fn build_org_map_from_peeringdb(
    glue: &GlueSet,
    opts: &PeeringDbBuildOptions,
) -> Result<OrgMap> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(&opts.user_agent)
        .timeout(Duration::from_secs(120))
        .build()?;

    let nets = fetch_all_nets(&client, opts)?;
    info!(nets = nets.len(), "fetched PeeringDB nets");

    let mut org_ids: Vec<u64> = nets.iter().map(|n| n.org_id).collect();
    org_ids.sort_unstable();
    org_ids.dedup();
    let orgs = fetch_orgs_by_ids(&client, &org_ids)?;
    info!(orgs = orgs.len(), "fetched PeeringDB orgs");

    let org_meta: HashMap<u64, &PdbOrg> = orgs.iter().map(|o| (o.id, o)).collect();

    let mut by_org: HashMap<u64, Vec<&PdbNet>> = HashMap::new();
    for net in &nets {
        by_org.entry(net.org_id).or_default().push(net);
    }

    let mut map = OrgMap::new();
    let mut skipped_glue = 0usize;
    let mut skipped_heuristic = 0usize;

    for (org_id, net_list) in by_org {
        let mut asns: Vec<u32> = net_list.iter().map(|n| n.asn).filter(|a| *a > 0).collect();
        asns.sort_unstable();
        asns.dedup();

        let subject_asns: Vec<u32> = asns
            .iter()
            .copied()
            .filter(|asn| opts.heuristics.is_subject(*asn, glue, None))
            .collect();
        if subject_asns.is_empty() {
            if asns.iter().any(|a| glue.contains(*a)) {
                skipped_glue += 1;
            } else {
                skipped_heuristic += 1;
            }
            continue;
        }

        let meta = org_meta.get(&org_id);
        let name = meta
            .map(|o| o.name.clone())
            .unwrap_or_else(|| format!("peeringdb-org-{org_id}"));

        let mut domains = Vec::new();
        if let Some(o) = meta {
            if let Some(w) = &o.website {
                if let Some(d) = website_to_domain(w) {
                    domains.push(d);
                }
            }
        }
        for net in &net_list {
            if let Some(w) = &net.website {
                if let Some(d) = website_to_domain(w) {
                    domains.push(d);
                }
            }
        }
        domains.sort();
        domains.dedup();

        map.insert(OrgRecord {
            org_id: format!("pdb:{org_id}"),
            name,
            asns: subject_asns,
            domains,
            prefix_count_hint: None,
            external_id: Some(format!("peeringdb_org:{org_id}")),
        });
    }

    info!(
        orgs = map.len(),
        skipped_glue, skipped_heuristic, "built OrgMap from PeeringDB"
    );
    Ok(map)
}

fn fetch_all_nets(
    client: &reqwest::blocking::Client,
    opts: &PeeringDbBuildOptions,
) -> Result<Vec<PdbNet>> {
    let mut out = Vec::new();
    let mut skip = 0usize;
    let mut pages = 0usize;
    loop {
        if opts.max_net_pages.is_some_and(|m| pages >= m) {
            break;
        }
        let url = format!("{PEERINGDB_NET}?limit={PAGE}&skip={skip}");
        let resp: PdbList<PdbNet> = get_json(client, &url)?;
        let n = resp.data.len();
        out.extend(resp.data);
        pages += 1;
        if pages % 20 == 0 {
            info!(pages, nets = out.len(), skip, "PeeringDB /net progress");
        }
        if n < PAGE {
            break;
        }
        skip += PAGE;
        thread::sleep(PAGE_DELAY);
    }
    Ok(out)
}

fn fetch_orgs_by_ids(client: &reqwest::blocking::Client, ids: &[u64]) -> Result<Vec<PdbOrg>> {
    let mut out = Vec::new();
    for (i, chunk) in ids.chunks(100).enumerate() {
        let id_list = chunk
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let url = format!("{PEERINGDB_ORG}?id__in={id_list}&limit=100");
        let resp: PdbList<PdbOrg> = get_json(client, &url)?;
        out.extend(resp.data);
        if (i + 1) % 20 == 0 {
            info!(chunks = i + 1, orgs = out.len(), "PeeringDB /org progress");
        }
        thread::sleep(PAGE_DELAY);
    }
    Ok(out)
}

fn get_json<T: for<'de> Deserialize<'de>>(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Result<T> {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let response = client
            .get(url)
            .send()
            .with_context(|| format!("GET {url}"))?;
        let status = response.status();
        if status.as_u16() == 429 || status.is_server_error() {
            if attempt > MAX_RETRIES {
                bail!("gave up after {MAX_RETRIES} retries for {url} (last status {status})");
            }
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or_else(|| 2u64.pow(attempt.min(6)));
            warn!(%status, retry_after, attempt, url, "PeeringDB rate limit / server error; backing off");
            // Consume body so connection can reuse.
            let _ = response.bytes();
            thread::sleep(Duration::from_secs(retry_after));
            continue;
        }
        let response = response
            .error_for_status()
            .with_context(|| format!("status for {url}"))?;
        return response.json().with_context(|| format!("json for {url}"));
    }
}

fn website_to_domain(website: &str) -> Option<String> {
    let w = website.trim();
    if w.is_empty() {
        return None;
    }
    let with_scheme = if w.contains("://") {
        w.to_string()
    } else {
        format!("https://{w}")
    };
    let url = url::Url::parse(&with_scheme).ok()?;
    let host = url.host_str()?;
    let d = normalize_domain(host);
    if d.is_empty() {
        None
    } else {
        Some(d)
    }
}

/// Write org map JSON wrapper for CLI consumption (lossy local copy).
///
/// PeeringDB is a **live** registry: `built_at` is crawl time, not historical BGP time.
/// Pass a `utc_iso` instant (`YYYY-MM-DDTHH:MM:SSZ`); do not use `to_rfc3339()`.
pub fn write_org_map_json(
    map: &OrgMap,
    path: impl AsRef<std::path::Path>,
    built_at: &str,
) -> Result<()> {
    #[derive(serde::Serialize)]
    struct Wrapper<'a> {
        source: &'static str,
        built_at: &'a str,
        orgs: Vec<&'a OrgRecord>,
    }
    let wrapper = Wrapper {
        source: "peeringdb",
        built_at,
        orgs: map.orgs().collect(),
    };
    let file = std::fs::File::create(path.as_ref())?;
    serde_json::to_writer_pretty(std::io::BufWriter::new(file), &wrapper)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn website_parsing() {
        assert_eq!(
            website_to_domain("https://www.Example.com/path").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            website_to_domain("cloudflare.com").as_deref(),
            Some("cloudflare.com")
        );
    }
}
