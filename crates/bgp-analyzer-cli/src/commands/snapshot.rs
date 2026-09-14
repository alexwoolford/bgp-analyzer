//! Origin-collapsed RIB snapshot command.
use anyhow::Result;
use bgp_ingest::{select_rib_baseline, DataType as MrtDataType, IngestQuery};
use bgp_ma::RibSnapshot;
use bgp_rib::Rib;
use tracing::{info, warn};

use super::common::{apply_elem_rib_only, ingest_into_rib, normalize_ts, parse_window_instant};
use crate::args::{SnapshotArgs, SnapshotMode};

pub fn run_snapshot(args: SnapshotArgs) -> Result<()> {
    let as_of = parse_window_instant(&args.end)?;
    let ts_start_dt = parse_window_instant(&args.start)?;
    let snap = build_snapshot(
        &args.start,
        &args.end,
        &args.collector,
        args.mode,
        args.skip_rib,
        args.max_updates,
    )?;
    // build_snapshot already stamps metadata; ensure as_of matches CLI end.
    let mut snap = snap;
    snap.as_of = as_of;
    snap.ts_start = Some(ts_start_dt);
    snap.collector = Some(args.collector.clone());
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    snap.save_json(&args.output)?;
    info!(
        path = %args.output.display(),
        prefixes = snap.prefixes.len(),
        as_of = %snap.as_of,
        source = ?snap.source,
        "wrote RIB snapshot"
    );
    Ok(())
}

pub fn build_snapshot(
    start_raw: &str,
    end_raw: &str,
    collector: &str,
    mode: SnapshotMode,
    skip_rib: bool,
    max_updates: Option<usize>,
) -> Result<RibSnapshot> {
    let ts_start = normalize_ts(start_raw)?;
    let ts_end = normalize_ts(end_raw)?;
    let as_of = parse_window_instant(end_raw)?;
    let ts_start_dt = parse_window_instant(start_raw)?;
    info!(
        %ts_start,
        %ts_end,
        collector,
        mode = ?mode,
        "building RIB snapshot"
    );

    let mut rib = Rib::new();
    let mut updates_seen = 0usize;
    let source = match mode {
        SnapshotMode::Rib => {
            let query = IngestQuery {
                ts_start: ts_start.clone(),
                ts_end: ts_end.clone(),
                collector: Some(collector.to_string()),
                data_type: MrtDataType::Rib,
            };
            let item = select_rib_baseline(&query)?;
            info!(url = %item.url, "loading RIB dump (M&A baseline)");
            let parser = bgp_ingest::open_parser(&item.url)?;
            for elem in parser {
                apply_elem_rib_only(&mut rib, &elem);
            }
            "rib"
        }
        SnapshotMode::Updates => {
            warn!("updates mode produces partial views; prefer --mode rib for day-over-day M&A");
            let query = IngestQuery {
                ts_start: ts_start.clone(),
                ts_end: ts_end.clone(),
                collector: Some(collector.to_string()),
                data_type: MrtDataType::Updates,
            };
            ingest_into_rib(&query, &mut rib, skip_rib, max_updates, &mut updates_seen)?;
            "updates"
        }
    };

    let mut snap = RibSnapshot::from_rib(&rib, as_of);
    snap.ts_start = Some(ts_start_dt);
    snap.collector = Some(collector.to_string());
    snap.source = Some(source.into());
    info!(
        prefixes = snap.prefixes.len(),
        updates = updates_seen,
        "snapshot built"
    );
    Ok(snap)
}
