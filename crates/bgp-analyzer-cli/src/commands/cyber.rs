//! Optional RPKI / valley-free analyze path.
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use bgp_detect::{maybe_alert, Alert, LeakDetector, PathVerdict};
use bgp_ingest::{plan_reconstruction, DataType as MrtDataType, IngestQuery};
use bgp_rib::{Rib, RouteEntry, RpkiState as RibRpkiState};
use bgp_rpki::{load_roas, RoasTrie, RpkiState};
use bgpkit_parser::models::ElemType;
use bgpkit_parser::BgpElem;
use tracing::{info, warn};

use super::common::{f64_to_datetime, normalize_ts};
use crate::args::AnalyzeArgs;

pub fn run_analyze(args: AnalyzeArgs) -> Result<()> {
    let ts_start = normalize_ts(&args.start)?;
    let ts_end = normalize_ts(&args.end)?;
    info!(%ts_start, %ts_end, collector = %args.collector, "starting cyber analyze (optional)");

    let roas = load_roas(&args.roas)?;
    let detector = LeakDetector::from_caida_path(&args.as_rel)?;
    let query = IngestQuery {
        ts_start: ts_start.clone(),
        ts_end: ts_end.clone(),
        collector: Some(args.collector.clone()),
        data_type: MrtDataType::Updates,
    };

    let mut rib = Rib::new();
    let mut alerts: Vec<Alert> = Vec::new();
    let mut updates_seen = 0usize;

    if !args.skip_rib {
        match plan_reconstruction(&query) {
            Ok(plan) => {
                info!(url = %plan.rib.url, "loading RIB baseline");
                let parser = bgp_ingest::open_parser(&plan.rib.url)?;
                for elem in parser {
                    apply_elem_cyber(
                        &mut rib,
                        &roas,
                        &detector,
                        &elem,
                        Some(&args.collector),
                        false,
                        &mut alerts,
                    );
                }
                for item in plan.updates {
                    if args.max_updates.is_some_and(|m| updates_seen >= m) {
                        break;
                    }
                    let parser = bgp_ingest::open_parser(&item.url)?;
                    for elem in parser {
                        if args.max_updates.is_some_and(|m| updates_seen >= m) {
                            break;
                        }
                        apply_elem_cyber(
                            &mut rib,
                            &roas,
                            &detector,
                            &elem,
                            Some(&args.collector),
                            true,
                            &mut alerts,
                        );
                        updates_seen += 1;
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "RIB planning failed; updates-only");
                cyber_updates_only(
                    &query,
                    &mut rib,
                    &roas,
                    &detector,
                    &args,
                    &mut alerts,
                    &mut updates_seen,
                )?;
            }
        }
    } else {
        cyber_updates_only(
            &query,
            &mut rib,
            &roas,
            &detector,
            &args,
            &mut alerts,
            &mut updates_seen,
        )?;
    }

    info!(
        alerts = alerts.len(),
        updates = updates_seen,
        "cyber analysis complete"
    );
    write_alert_jsonl(&args.output, &alerts)?;
    Ok(())
}

pub fn cyber_updates_only(
    query: &IngestQuery,
    rib: &mut Rib,
    roas: &RoasTrie,
    detector: &LeakDetector,
    args: &AnalyzeArgs,
    alerts: &mut Vec<Alert>,
    updates_seen: &mut usize,
) -> Result<()> {
    let updates = bgp_ingest::list_updates(query)?;
    for item in updates {
        if args.max_updates.is_some_and(|m| *updates_seen >= m) {
            break;
        }
        let parser = bgp_ingest::open_parser(&item.url)?;
        for elem in parser {
            if args.max_updates.is_some_and(|m| *updates_seen >= m) {
                break;
            }
            apply_elem_cyber(
                rib,
                roas,
                detector,
                &elem,
                Some(&args.collector),
                true,
                alerts,
            );
            *updates_seen += 1;
        }
    }
    Ok(())
}

pub fn apply_elem_cyber(
    rib: &mut Rib,
    roas: &RoasTrie,
    detector: &LeakDetector,
    elem: &BgpElem,
    collector: Option<&str>,
    emit_alerts: bool,
    alerts: &mut Vec<Alert>,
) {
    let prefix = elem.prefix.prefix;
    let peer_asn = elem.peer_asn.to_u32();
    if elem.elem_type == ElemType::WITHDRAW {
        rib.withdraw(prefix, peer_asn);
        return;
    }
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
    let rpki = match origin_asn {
        Some(asn) => roas.validate(prefix, asn),
        None => RpkiState::Unknown,
    };
    let path_id = rib.interner.intern_as_path(&as_path);
    rib.announce(
        prefix,
        RouteEntry {
            origin_asn,
            as_path_id: path_id,
            peer_asn,
            communities_id: None,
            rpki: rib_rpki(rpki),
            timestamp: elem.timestamp,
        },
    );
    if !emit_alerts {
        return;
    }
    let verdict = if as_path.is_empty() {
        PathVerdict::TooShort
    } else {
        detector.check_as_path(&as_path)
    };
    if let Some(alert) = maybe_alert(
        f64_to_datetime(elem.timestamp),
        prefix,
        origin_asn,
        as_path,
        peer_asn,
        collector.map(|s| s.to_string()),
        rpki,
        verdict,
    ) {
        alerts.push(alert);
    }
}

fn rib_rpki(state: RpkiState) -> RibRpkiState {
    match state {
        RpkiState::Valid => RibRpkiState::Valid,
        RpkiState::Invalid => RibRpkiState::Invalid,
        RpkiState::Unknown => RibRpkiState::Unknown,
    }
}

pub fn write_alert_jsonl(path: &PathBuf, alerts: &[Alert]) -> Result<()> {
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = BufWriter::new(file);
    for alert in alerts {
        serde_json::to_writer(&mut w, alert)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}
