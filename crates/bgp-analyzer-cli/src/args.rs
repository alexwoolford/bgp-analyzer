//! Clap CLI surface for bgp-analyzer.
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "bgp-analyzer",
    version,
    about = "BGP M&A network-contact analyzer (ma-diff) with optional RPKI/valley-free cyber analysis"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Build ASN↔org↔domain map from the live PeeringDB API (required before ma-diff).
    BuildOrgMap(BuildOrgMapArgs),
    /// Build an origin-collapsed RIB snapshot JSON from historical MRT (for ma-diff).
    Snapshot(SnapshotArgs),
    /// Diff two real RIB snapshots into M&A network-contact events (primary product path).
    MaDiff(MaDiffArgs),
    /// Consecutive RIB day snapshots + diffs + pair features (historical backtest).
    Backtest(BacktestArgs),
    /// Thin daily signal: prior snapshot → today RIB → sparse events; prune old snapshots.
    Daily(DailyArgs),
    /// Score known-positive eval cases against an events JSONL (hit/miss).
    Eval(EvalArgs),
    /// Optional cyber path: RPKI ROV + valley-free leak heuristics.
    Analyze(AnalyzeArgs),
}

#[derive(Debug, Parser)]
pub struct BuildOrgMapArgs {
    /// Work sqlite directory (`bgp-analyzer.sqlite` is the system of record).
    #[arg(long, env = "BGP_DAILY_STATE", default_value = "data/daily")]
    pub state_dir: PathBuf,
    /// Optional JSON dump after sqlite commit (lossy local copy).
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Glue ASN suppress list (real public ASNs).
    #[arg(long, env = "BGP_GLUE", default_value = "fixtures/glue-asns.txt")]
    pub glue: PathBuf,
    /// Cap PeeringDB `/net` pages (250 nets/page). Omit for full crawl.
    #[arg(long)]
    pub max_net_pages: Option<usize>,
}

/// How to build a snapshot. Prefer `rib` for day-over-day M&A baselines.
#[derive(Debug, Clone, ValueEnum, Default)]
pub enum SnapshotMode {
    /// Load the latest RIB dump in the window (default M&A path).
    #[default]
    Rib,
    /// Updates-driven reconstruction (debug / partial views). Prefer with explicit caps.
    Updates,
}

#[derive(Debug, Parser)]
pub struct SnapshotArgs {
    #[arg(long)]
    pub start: String,
    #[arg(long)]
    pub end: String,
    #[arg(long, default_value = "route-views2")]
    pub collector: String,
    #[arg(long, default_value = "rib-snapshot.json")]
    pub output: PathBuf,
    /// Snapshot source: `rib` (default) or `updates` (debug).
    #[arg(long, value_enum, default_value_t = SnapshotMode::Rib)]
    pub mode: SnapshotMode,
    /// Cap updates applied (updates mode / reconstruction only).
    #[arg(long)]
    pub max_updates: Option<usize>,
    /// Updates mode: skip RIB baseline and apply updates only (partial view; debug).
    #[arg(long, default_value_t = false)]
    pub skip_rib: bool,
}

#[derive(Debug, Parser)]
pub struct MaDiffArgs {
    /// Earlier RIB snapshot JSON.
    #[arg(long)]
    pub before: PathBuf,
    /// Later RIB snapshot JSON.
    #[arg(long)]
    pub after: PathBuf,
    /// Org map JSON (`{ "orgs": [ ... ] }`).
    #[arg(long)]
    pub org_map: PathBuf,
    /// Glue ASN suppress list (default: fixtures/glue-asns.txt if present, else builtin).
    #[arg(long)]
    pub glue: Option<PathBuf>,
    /// Optional domain watchlist to enrich org domains (not a gate; one domain per line).
    #[arg(long)]
    pub extra_domains: Option<PathBuf>,
    #[arg(long, default_value = "ma-events.jsonl")]
    pub output: PathBuf,
    #[arg(long, default_value_t = 0.25)]
    pub footprint_rel_threshold: f64,
    #[arg(long, default_value_t = 5)]
    pub footprint_abs_threshold: u32,
}

#[derive(Debug, Parser)]
pub struct EvalArgs {
    /// M&A events JSONL from `ma-diff` / `backtest`.
    #[arg(long)]
    pub events: Option<PathBuf>,
    /// Pair features JSONL from `backtest` (scores cases against aggregated pairs).
    #[arg(long)]
    pub features: Option<PathBuf>,
    /// Eval cases JSONL (see fixtures/eval/).
    #[arg(long, default_value = "fixtures/eval/cases.jsonl")]
    pub cases: PathBuf,
    /// Optional JSONL of per-case results.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
pub struct BacktestArgs {
    /// First calendar day (UTC), YYYY-MM-DD.
    #[arg(long)]
    pub start: String,
    /// Number of consecutive calendar days in the window (inclusive span length).
    #[arg(long, default_value_t = 30)]
    pub days: u32,
    /// Sample every N calendar days (1 = daily). Use 7 for lead-lag smoke runs.
    #[arg(long, default_value_t = 1)]
    pub step_days: u32,
    #[arg(long, default_value = "route-views2")]
    pub collector: String,
    #[arg(long)]
    pub org_map: PathBuf,
    /// Optional JSON org-map overlay merged on top (e.g. fixtures/eval/org-map-overlay.json).
    #[arg(long)]
    pub org_map_overlay: Option<PathBuf>,
    #[arg(long)]
    pub glue: Option<PathBuf>,
    /// Output directory: snapshots/, events/, pair-features.jsonl, eval-report.json
    #[arg(long, default_value = "data/backtest")]
    pub out_dir: PathBuf,
    /// Optional shared snapshot directory (reuse across overlapping deal windows).
    #[arg(long)]
    pub snapshot_dir: Option<PathBuf>,
    /// Reuse existing snapshot JSON files if present.
    #[arg(long, default_value_t = false)]
    pub skip_fetch: bool,
    /// Optional known-positive cases for hit/miss scoring after aggregation.
    #[arg(long, default_value = "fixtures/eval/cases.jsonl")]
    pub cases: PathBuf,
    #[arg(long, default_value_t = 0.25)]
    pub footprint_rel_threshold: f64,
    #[arg(long, default_value_t = 5)]
    pub footprint_abs_threshold: u32,
    /// Comma-separated ASNs to retain in snapshots (origins/paths). Default: ASNs from --cases.
    #[arg(long)]
    pub focus_asns: Option<String>,
}

#[derive(Debug, Parser)]
pub struct DailyArgs {
    /// State directory (work sqlite + snapshots/ + events/ + signals/).
    #[arg(long, env = "BGP_DAILY_STATE", default_value = "data/daily")]
    pub state_dir: PathBuf,
    /// Calendar day to process (UTC), YYYY-MM-DD. Default: today UTC.
    #[arg(long)]
    pub date: Option<String>,
    #[arg(long, env = "BGP_COLLECTOR", default_value = "route-views2")]
    pub collector: String,
    /// Optional JSON org-map overlay / legacy merge on top of sqlite orgs.
    #[arg(long)]
    pub org_map: Option<PathBuf>,
    /// Optional org-map overlay JSON (same shape as build-org-map output).
    #[arg(long)]
    pub org_map_overlay: Option<PathBuf>,
    /// Refuse if `org_map_runs.finished_at` is older than this many days.
    #[arg(long, env = "ORG_MAP_MAX_AGE_DAYS", default_value_t = 14)]
    pub org_map_max_age_days: i64,
    #[arg(long, env = "BGP_GLUE")]
    pub glue: Option<PathBuf>,
    /// Keep this many calendar days of snapshots (prune older).
    #[arg(long, default_value_t = 7)]
    pub retain_days: u32,
    /// Rolling pair-state retention (days) for persistence on emitted signals.
    #[arg(long, default_value_t = 30)]
    pub pair_state_days: i64,
    /// Disable sparse filter (emit full ma-diff for the day).
    #[arg(long, default_value_t = false)]
    pub full: bool,
    /// Sparse: min prefix_move count per ASN pair per day (default 2).
    #[arg(long, default_value_t = 2)]
    pub min_prefix_moves: u32,
    #[arg(long, default_value_t = 0.25)]
    pub footprint_rel_threshold: f64,
    #[arg(long, default_value_t = 5)]
    pub footprint_abs_threshold: u32,
    /// Comma-separated ASNs to retain in snapshots (origins).
    #[arg(long)]
    pub focus_asns: Option<String>,
    /// Focus snapshots on subject ASNs from the org map using RIB origin prefix counts.
    #[arg(long, default_value_t = false)]
    pub focus_from_org_map: bool,
    /// Skip same-org / glue / leasing / unattributed / family clean before signal emit.
    #[arg(long, default_value_t = false)]
    pub no_clean: bool,
    /// Do not append to signals/inbox.jsonl.
    #[arg(long, default_value_t = false)]
    pub no_inbox: bool,
    /// Write intermediate events/ and pair-features JSONL (debug hose).
    #[arg(long, default_value_t = false)]
    pub debug_jsonl: bool,
}

#[derive(Debug, Parser)]
pub struct AnalyzeArgs {
    #[arg(long)]
    pub start: String,
    #[arg(long)]
    pub end: String,
    #[arg(long, default_value = "route-views2")]
    pub collector: String,
    #[arg(long)]
    pub as_rel: String,
    #[arg(long)]
    pub roas: String,
    #[arg(long, default_value = "data/cyber/alerts.jsonl")]
    pub output: PathBuf,
    #[arg(long)]
    pub max_updates: Option<usize>,
    #[arg(long, default_value_t = false)]
    pub skip_rib: bool,
}
