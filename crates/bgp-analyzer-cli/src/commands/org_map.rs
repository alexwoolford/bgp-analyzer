//! PeeringDB org-map builder command.
use anyhow::Result;
use bgp_map::{
    build_org_map_from_peeringdb, write_org_map_json, GlueSet, PeeringDbBuildOptions,
    SubjectHeuristics,
};
use bgp_state::{work_db_path, WorkDb};
use chrono::Utc;
use tracing::info;

use crate::args::BuildOrgMapArgs;

pub fn run_build_org_map(args: BuildOrgMapArgs) -> Result<()> {
    let started_at = Utc::now();
    let glue = GlueSet::from_file(&args.glue)?;
    let opts = PeeringDbBuildOptions {
        heuristics: SubjectHeuristics::default(),
        max_net_pages: args.max_net_pages,
        ..PeeringDbBuildOptions::default()
    };
    info!(
        glue = glue.len(),
        max_net_pages = ?args.max_net_pages,
        state_dir = %args.state_dir.display(),
        "building org map from live PeeringDB (real data only)"
    );
    let map = build_org_map_from_peeringdb(&glue, &opts)?;
    std::fs::create_dir_all(&args.state_dir)?;
    let sqlite = work_db_path(&args.state_dir);
    let mut db = WorkDb::open(&sqlite)?;
    let commit = db.commit_org_map(&map, started_at)?;
    if let Some(output) = &args.output {
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_org_map_json(&map, output, &commit.built_at)?;
        info!(path = %output.display(), "wrote org-map JSON copy");
    }
    info!(
        sqlite = %sqlite.display(),
        orgs = commit.org_count,
        built_at = %commit.built_at,
        "committed PeeringDB org map"
    );
    Ok(())
}
