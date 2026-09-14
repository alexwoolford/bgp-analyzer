//! `ma-diff` subcommand.
use anyhow::Result;
use bgp_ma::{diff_snapshots, write_ma_events_jsonl, DiffConfig, RibSnapshot};
use bgp_map::SubjectHeuristics;
use tracing::info;

use super::common::{load_glue, load_org_map};
use crate::args::MaDiffArgs;

pub fn run_ma_diff(args: MaDiffArgs) -> Result<()> {
    let before = RibSnapshot::load_json(&args.before)?;
    let after = RibSnapshot::load_json(&args.after)?;
    let org_map = load_org_map(&args.org_map, args.extra_domains.as_ref(), None)?;
    let glue = load_glue(args.glue.as_ref())?;

    let cfg = DiffConfig {
        heuristics: SubjectHeuristics::default(),
        footprint_rel_threshold: args.footprint_rel_threshold,
        footprint_abs_threshold: args.footprint_abs_threshold,
    };

    let events = diff_snapshots(&before, &after, &org_map, &glue, &cfg);
    write_ma_events_jsonl(&args.output, &events)?;
    info!(
        path = %args.output.display(),
        events = events.len(),
        "wrote M&A network-contact events"
    );
    Ok(())
}
