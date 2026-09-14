//! Subcommand implementations.

mod backtest;
mod common;
mod cyber;
mod daily;
mod diff;
mod eval;
mod org_map;
mod snapshot;

pub use backtest::{
    announce_day, build_lead_lag_rows, horizon_bucket, pair_contact_in_window, run_backtest,
    target_footprint_hit, LeadLagRow,
};
pub use common::{
    apply_elem_rib_only, apply_rib_announcement, apply_updates_only, f64_to_datetime,
    filter_snapshot_focus, find_prior_snapshot, ingest_into_rib, load_glue, load_org_map,
    normalize_ts, parse_window_instant, parse_ymd, prune_snapshots, rib_announcement_from_elem,
    RibAnnouncement,
};
pub use cyber::{apply_elem_cyber, cyber_updates_only, run_analyze, write_alert_jsonl};
pub use daily::run_daily;
pub use diff::run_ma_diff;
pub use eval::{run_eval, write_eval_results};
pub use org_map::run_build_org_map;
pub use snapshot::{build_snapshot, run_snapshot};
