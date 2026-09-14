//! Shared CLI helpers (dates, glue, snapshots, RIB apply).
use std::path::PathBuf;

use anyhow::{Context, Result};
use bgp_ingest::{plan_reconstruction, IngestQuery};
use bgp_ma::RibSnapshot;
use bgp_map::{GlueSet, OrgMap};
use bgp_rib::{Rib, RouteEntry, RpkiState as RibRpkiState};
use bgpkit_parser::models::ElemType;
use bgpkit_parser::BgpElem;
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use tracing::{info, warn};

pub fn load_org_map(
    path: &PathBuf,
    extra: Option<&PathBuf>,
    overlay: Option<&PathBuf>,
) -> Result<OrgMap> {
    let mut org_map = OrgMap::from_json_file(path)?;
    if let Some(overlay) = overlay {
        apply_org_overlay(&mut org_map, overlay)?;
    }
    if let Some(extra) = extra {
        org_map.enrich_domains_from_watchlist(extra)?;
    }
    Ok(org_map)
}

pub(crate) fn apply_org_overlay(map: &mut OrgMap, overlay: &PathBuf) -> Result<()> {
    let overlay_map = OrgMap::from_json_file(overlay)?;
    let n = overlay_map.len();
    for org in overlay_map.orgs() {
        map.insert(org.clone());
    }
    info!(overlay = %overlay.display(), orgs = n, "merged org-map overlay");
    Ok(())
}

pub fn filter_snapshot_focus(snap: &mut RibSnapshot, focus: &std::collections::HashSet<u32>) {
    snap.prefixes
        .retain(|_, obs| focus.contains(&obs.origin_asn));
}

pub fn load_glue(glue: Option<&PathBuf>) -> Result<GlueSet> {
    match glue {
        Some(path) => GlueSet::from_file(path),
        None => {
            let default = PathBuf::from("fixtures/glue-asns.txt");
            if default.exists() {
                GlueSet::from_file(&default)
            } else {
                warn!("no --glue and fixtures/glue-asns.txt missing; using builtin glue set");
                Ok(GlueSet::builtin())
            }
        }
    }
}

pub fn parse_ymd(raw: &str) -> Result<NaiveDate> {
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .with_context(|| format!("parsing date `{raw}` (expected YYYY-MM-DD)"))
}

pub fn find_prior_snapshot(snap_dir: &std::path::Path, day: NaiveDate) -> Result<Option<PathBuf>> {
    let mut best: Option<(NaiveDate, PathBuf)> = None;
    if !snap_dir.exists() {
        return Ok(None);
    }
    for ent in std::fs::read_dir(snap_dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name
            .strip_prefix("rib-")
            .and_then(|s| s.strip_suffix(".json"))
        else {
            continue;
        };
        let Ok(d) = NaiveDate::parse_from_str(rest, "%Y-%m-%d") else {
            continue;
        };
        if d >= day {
            continue;
        }
        if best.as_ref().map(|(bd, _)| d > *bd).unwrap_or(true) {
            best = Some((d, ent.path()));
        }
    }
    Ok(best.map(|(_, p)| p))
}

pub fn prune_snapshots(
    snap_dir: &std::path::Path,
    as_of_day: NaiveDate,
    retain_days: u32,
) -> Result<()> {
    let cutoff = as_of_day
        .checked_sub_signed(Duration::days(retain_days as i64))
        .context("retain cutoff overflow")?;
    if !snap_dir.exists() {
        return Ok(());
    }
    for ent in std::fs::read_dir(snap_dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name
            .strip_prefix("rib-")
            .and_then(|s| s.strip_suffix(".json"))
        else {
            continue;
        };
        let Ok(d) = NaiveDate::parse_from_str(rest, "%Y-%m-%d") else {
            continue;
        };
        if d < cutoff {
            info!(path = %ent.path().display(), %d, %cutoff, "pruning old snapshot");
            std::fs::remove_file(ent.path())?;
        }
    }
    Ok(())
}

pub fn ingest_into_rib(
    query: &IngestQuery,
    rib: &mut Rib,
    skip_rib: bool,
    max_updates: Option<usize>,
    updates_seen: &mut usize,
) -> Result<()> {
    if !skip_rib {
        match plan_reconstruction(query) {
            Ok(plan) => {
                info!(url = %plan.rib.url, "loading RIB baseline");
                let parser = bgp_ingest::open_parser(&plan.rib.url)?;
                for elem in parser {
                    apply_elem_rib_only(rib, &elem);
                }
                for item in plan.updates {
                    if max_updates.is_some_and(|m| *updates_seen >= m) {
                        break;
                    }
                    info!(url = %item.url, "applying updates file");
                    let parser = bgp_ingest::open_parser(&item.url)?;
                    for elem in parser {
                        if max_updates.is_some_and(|m| *updates_seen >= m) {
                            break;
                        }
                        apply_elem_rib_only(rib, &elem);
                        *updates_seen += 1;
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "RIB planning failed; updates-only");
                apply_updates_only(query, rib, max_updates, updates_seen)?;
            }
        }
    } else {
        apply_updates_only(query, rib, max_updates, updates_seen)?;
    }
    Ok(())
}

pub fn apply_updates_only(
    query: &IngestQuery,
    rib: &mut Rib,
    max_updates: Option<usize>,
    updates_seen: &mut usize,
) -> Result<()> {
    let updates = bgp_ingest::list_updates(query)?;
    for item in updates {
        if max_updates.is_some_and(|m| *updates_seen >= m) {
            break;
        }
        info!(url = %item.url, "applying updates file");
        let parser = bgp_ingest::open_parser(&item.url)?;
        for elem in parser {
            if max_updates.is_some_and(|m| *updates_seen >= m) {
                break;
            }
            apply_elem_rib_only(rib, &elem);
            *updates_seen += 1;
        }
    }
    Ok(())
}

pub fn apply_elem_rib_only(rib: &mut Rib, elem: &BgpElem) {
    apply_rib_announcement(rib, &rib_announcement_from_elem(elem));
}

/// RIB mutation that does not depend on `BgpElem` (unit-testable).
#[derive(Debug, Clone)]
pub struct RibAnnouncement {
    pub prefix: ipnet::IpNet,
    pub peer_asn: u32,
    pub withdraw: bool,
    pub as_path: Vec<u32>,
    pub origin_asn: Option<u32>,
    pub timestamp: f64,
}

pub fn rib_announcement_from_elem(elem: &BgpElem) -> RibAnnouncement {
    let as_path: Vec<u32> = elem
        .as_path
        .as_ref()
        .and_then(|p| p.to_u32_vec_opt(false))
        .unwrap_or_default();
    let origin_asn = elem
        .origin_asns
        .as_ref()
        .and_then(|o| o.first().map(|a| a.to_u32()))
        .or_else(|| as_path.last().copied());
    RibAnnouncement {
        prefix: elem.prefix.prefix,
        peer_asn: elem.peer_asn.to_u32(),
        withdraw: elem.elem_type == ElemType::WITHDRAW,
        as_path,
        origin_asn,
        timestamp: elem.timestamp,
    }
}

pub fn apply_rib_announcement(rib: &mut Rib, update: &RibAnnouncement) {
    if update.withdraw {
        rib.withdraw(update.prefix, update.peer_asn);
        return;
    }
    let path_id = rib.interner.intern_as_path(&update.as_path);
    rib.announce(
        update.prefix,
        RouteEntry {
            origin_asn: update.origin_asn,
            as_path_id: path_id,
            peer_asn: update.peer_asn,
            communities_id: None,
            rpki: RibRpkiState::Unknown,
            timestamp: update.timestamp,
        },
    );
}

// --- optional cyber analyze path (demoted) ---

pub fn normalize_ts(raw: &str) -> Result<String> {
    if raw.chars().all(|c| c.is_ascii_digit()) {
        return Ok(raw.to_string());
    }
    let dt = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("parsing timestamp `{raw}`"))?
        .with_timezone(&Utc);
    Ok(dt.timestamp().to_string())
}

/// Parse CLI window bounds into UTC (RFC3339 or unix seconds).
pub fn parse_window_instant(raw: &str) -> Result<DateTime<Utc>> {
    if raw.chars().all(|c| c.is_ascii_digit()) {
        let secs: i64 = raw
            .parse()
            .with_context(|| format!("parsing unix timestamp `{raw}`"))?;
        return Utc
            .timestamp_opt(secs, 0)
            .single()
            .with_context(|| format!("invalid unix timestamp `{raw}`"));
    }
    Ok(DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("parsing timestamp `{raw}`"))?
        .with_timezone(&Utc))
}

pub fn f64_to_datetime(ts: f64) -> DateTime<Utc> {
    let secs = ts.floor() as i64;
    let nsecs = ((ts - secs as f64) * 1_000_000_000.0) as u32;
    Utc.timestamp_opt(secs, nsecs).single().unwrap_or_else(|| {
        Utc.timestamp_opt(secs, 0)
            .single()
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
    })
}
