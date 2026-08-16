//! BGP Analyzer CLI — M&A network-contact diffs (primary) + optional cyber analyze.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use arrow_array::{
    ArrayRef, BooleanArray, ListArray, RecordBatch, StringArray, UInt32Array,
};
use arrow_schema::{DataType, Field, Schema};
use bgp_detect::{maybe_alert, Alert, LeakDetector, PathVerdict};
use bgp_ingest::{plan_reconstruction, select_rib_baseline, DataType as MrtDataType, IngestQuery};
use bgp_ma::{
    aggregate_pair_features, append_inbox_jsonl, build_signals, canon_pair, diff_snapshots,
    eval_cases, eval_cases_against_features, filter_clean_features, filter_sparse_events,
    leasing_set, load_eval_cases, load_ma_events, score_backtest, write_ma_events_jsonl,
    write_pair_features_jsonl, write_signals_jsonl, AsnPairFeature, DiffConfig, EvalCase,
    EvalCaseResult, MaEvent, MaEventKind, PairStateStore, RibSnapshot, SparseConfig,
};
use bgp_map::{
    build_org_map_from_peeringdb, write_org_map_json, GlueSet, OrgMap, PeeringDbBuildOptions,
    SubjectHeuristics,
};
use bgp_rib::{Rib, RouteEntry};
use bgp_rpki::{load_roas, RoasTrie, RpkiState};
use bgpkit_parser::models::ElemType;
use bgpkit_parser::BgpElem;
use chrono::{DateTime, Duration, NaiveDate, TimeZone, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use parquet::arrow::ArrowWriter;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(
    name = "bgp-analyzer",
    version,
    about = "BGP M&A network-contact analyzer (ma-diff) with optional RPKI/valley-free cyber analysis"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
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
struct BuildOrgMapArgs {
    /// Output org-map JSON path (prefer dated: data/org-map-peeringdb-YYYY-MM-DD.json).
    #[arg(long, default_value = "data/org-map-peeringdb.json")]
    output: PathBuf,
    /// Glue ASN suppress list (real public ASNs).
    #[arg(long, default_value = "fixtures/glue-asns.txt")]
    glue: PathBuf,
    /// Cap PeeringDB `/net` pages (250 nets/page). Omit for full crawl.
    #[arg(long)]
    max_net_pages: Option<usize>,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Jsonl,
    Parquet,
}

/// How to build a snapshot. Prefer `rib` for day-over-day M&A baselines.
#[derive(Debug, Clone, ValueEnum, Default)]
enum SnapshotMode {
    /// Load the latest RIB dump in the window (default M&A path).
    #[default]
    Rib,
    /// Updates-driven reconstruction (debug / partial views). Prefer with explicit caps.
    Updates,
}

#[derive(Debug, Parser)]
struct SnapshotArgs {
    #[arg(long)]
    start: String,
    #[arg(long)]
    end: String,
    #[arg(long, default_value = "route-views2")]
    collector: String,
    #[arg(long, default_value = "rib-snapshot.json")]
    output: PathBuf,
    /// Snapshot source: `rib` (default) or `updates` (debug).
    #[arg(long, value_enum, default_value_t = SnapshotMode::Rib)]
    mode: SnapshotMode,
    /// Cap updates applied (updates mode / reconstruction only).
    #[arg(long)]
    max_updates: Option<usize>,
    /// Updates mode: skip RIB baseline and apply updates only (partial view; debug).
    #[arg(long, default_value_t = false)]
    skip_rib: bool,
}

#[derive(Debug, Parser)]
struct MaDiffArgs {
    /// Earlier RIB snapshot JSON.
    #[arg(long)]
    before: PathBuf,
    /// Later RIB snapshot JSON.
    #[arg(long)]
    after: PathBuf,
    /// Org map JSON (`{ "orgs": [ ... ] }`).
    #[arg(long)]
    org_map: PathBuf,
    /// Glue ASN suppress list (default: fixtures/glue-asns.txt if present, else builtin).
    #[arg(long)]
    glue: Option<PathBuf>,
    /// Optional domain watchlist to enrich org domains (not a gate; one domain per line).
    #[arg(long)]
    extra_domains: Option<PathBuf>,
    #[arg(long, default_value = "ma-events.jsonl")]
    output: PathBuf,
    #[arg(long, default_value_t = 0.25)]
    footprint_rel_threshold: f64,
    #[arg(long, default_value_t = 5)]
    footprint_abs_threshold: u32,
}

#[derive(Debug, Parser)]
struct EvalArgs {
    /// M&A events JSONL from `ma-diff` / `backtest`.
    #[arg(long)]
    events: Option<PathBuf>,
    /// Pair features JSONL from `backtest` (scores cases against aggregated pairs).
    #[arg(long)]
    features: Option<PathBuf>,
    /// Eval cases JSONL (see fixtures/eval/).
    #[arg(long, default_value = "fixtures/eval/cases.jsonl")]
    cases: PathBuf,
    /// Optional JSONL of per-case results.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct BacktestArgs {
    /// First calendar day (UTC), YYYY-MM-DD.
    #[arg(long)]
    start: String,
    /// Number of consecutive calendar days in the window (inclusive span length).
    #[arg(long, default_value_t = 30)]
    days: u32,
    /// Sample every N calendar days (1 = daily). Use 7 for lead-lag smoke runs.
    #[arg(long, default_value_t = 1)]
    step_days: u32,
    #[arg(long, default_value = "route-views2")]
    collector: String,
    #[arg(long)]
    org_map: PathBuf,
    /// Optional JSON org-map overlay merged on top (e.g. fixtures/eval/org-map-overlay.json).
    #[arg(long)]
    org_map_overlay: Option<PathBuf>,
    #[arg(long)]
    glue: Option<PathBuf>,
    /// Output directory: snapshots/, events/, pair-features.jsonl, eval-report.json
    #[arg(long, default_value = "data/backtest")]
    out_dir: PathBuf,
    /// Optional shared snapshot directory (reuse across overlapping deal windows).
    #[arg(long)]
    snapshot_dir: Option<PathBuf>,
    /// Reuse existing snapshot JSON files if present.
    #[arg(long, default_value_t = false)]
    skip_fetch: bool,
    /// Optional known-positive cases for hit/miss scoring after aggregation.
    #[arg(long, default_value = "fixtures/eval/cases.jsonl")]
    cases: PathBuf,
    #[arg(long, default_value_t = 0.25)]
    footprint_rel_threshold: f64,
    #[arg(long, default_value_t = 5)]
    footprint_abs_threshold: u32,
    /// Comma-separated ASNs to retain in snapshots (origins/paths). Default: ASNs from --cases.
    #[arg(long)]
    focus_asns: Option<String>,
}

#[derive(Debug, Parser)]
struct DailyArgs {
    /// State directory (snapshots/ + events/ + signals/ + pair-state.json).
    #[arg(long, default_value = "data/daily")]
    state_dir: PathBuf,
    /// Calendar day to process (UTC), YYYY-MM-DD. Default: today UTC.
    #[arg(long)]
    date: Option<String>,
    #[arg(long, default_value = "route-views2")]
    collector: String,
    #[arg(long)]
    org_map: PathBuf,
    /// Optional org-map overlay JSON (same shape as build-org-map output).
    #[arg(long)]
    org_map_overlay: Option<PathBuf>,
    #[arg(long)]
    glue: Option<PathBuf>,
    /// Keep this many calendar days of snapshots (prune older).
    #[arg(long, default_value_t = 7)]
    retain_days: u32,
    /// Rolling pair-state retention (days) for persistence on emitted signals.
    #[arg(long, default_value_t = 30)]
    pair_state_days: i64,
    /// Disable sparse filter (emit full ma-diff for the day).
    #[arg(long, default_value_t = false)]
    full: bool,
    /// Sparse: min prefix_move count per ASN pair per day (default 2).
    #[arg(long, default_value_t = 2)]
    min_prefix_moves: u32,
    #[arg(long, default_value_t = 0.25)]
    footprint_rel_threshold: f64,
    #[arg(long, default_value_t = 5)]
    footprint_abs_threshold: u32,
    /// Comma-separated ASNs to retain in snapshots (origins/paths).
    #[arg(long)]
    focus_asns: Option<String>,
    /// Focus snapshots on subject ASNs from the org map (SubjectHeuristics).
    #[arg(long, default_value_t = false)]
    focus_from_org_map: bool,
    /// Skip same-org / leasing clean before signal emit.
    #[arg(long, default_value_t = false)]
    no_clean: bool,
    /// Do not append to signals/inbox.jsonl.
    #[arg(long, default_value_t = false)]
    no_inbox: bool,
}

#[derive(Debug, Parser)]
struct AnalyzeArgs {
    #[arg(long)]
    start: String,
    #[arg(long)]
    end: String,
    #[arg(long, default_value = "route-views2")]
    collector: String,
    #[arg(long)]
    as_rel: String,
    #[arg(long)]
    roas: String,
    #[arg(long, default_value = "data/cyber/alerts.jsonl")]
    output: PathBuf,
    #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl)]
    format: OutputFormat,
    #[arg(long)]
    max_updates: Option<usize>,
    #[arg(long, default_value_t = false)]
    skip_rib: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::BuildOrgMap(args) => run_build_org_map(args),
        Commands::Snapshot(args) => run_snapshot(args),
        Commands::MaDiff(args) => run_ma_diff(args),
        Commands::Backtest(args) => run_backtest(args),
        Commands::Daily(args) => run_daily(args),
        Commands::Eval(args) => run_eval(args),
        Commands::Analyze(args) => run_analyze(args),
    }
}

fn run_build_org_map(args: BuildOrgMapArgs) -> Result<()> {
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let glue = GlueSet::from_file(&args.glue)?;
    let opts = PeeringDbBuildOptions {
        heuristics: SubjectHeuristics::default(),
        max_net_pages: args.max_net_pages,
        ..PeeringDbBuildOptions::default()
    };
    info!(
        glue = glue.len(),
        max_net_pages = ?args.max_net_pages,
        "building org map from live PeeringDB (real data only)"
    );
    let map = build_org_map_from_peeringdb(&glue, &opts)?;
    write_org_map_json(&map, &args.output)?;
    info!(
        path = %args.output.display(),
        orgs = map.len(),
        "wrote PeeringDB org map"
    );
    Ok(())
}

fn run_snapshot(args: SnapshotArgs) -> Result<()> {
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

fn run_ma_diff(args: MaDiffArgs) -> Result<()> {
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

fn run_backtest(args: BacktestArgs) -> Result<()> {
    let start_day = parse_ymd(&args.start)?;
    if args.days == 0 {
        anyhow::bail!("--days must be >= 1");
    }
    if args.step_days == 0 {
        anyhow::bail!("--step-days must be >= 1");
    }
    let snap_dir = args
        .snapshot_dir
        .clone()
        .unwrap_or_else(|| args.out_dir.join("snapshots"));
    let events_dir = args.out_dir.join("events");
    std::fs::create_dir_all(&snap_dir)?;
    std::fs::create_dir_all(&events_dir)?;

    let org_map = load_org_map(&args.org_map, None, args.org_map_overlay.as_ref())?;
    let glue = load_glue(args.glue.as_ref())?;
    let cfg = DiffConfig {
        heuristics: SubjectHeuristics::default(),
        footprint_rel_threshold: args.footprint_rel_threshold,
        footprint_abs_threshold: args.footprint_abs_threshold,
    };

    let mut focus: std::collections::HashSet<u32> = std::collections::HashSet::new();
    if let Some(raw) = &args.focus_asns {
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            focus.insert(part.parse().with_context(|| format!("invalid --focus-asns entry `{part}`"))?);
        }
    }
    if args.cases.exists() {
        for c in load_eval_cases(&args.cases)? {
            focus.insert(c.asn_a);
            if let Some(b) = c.asn_b {
                focus.insert(b);
            }
        }
    }
    info!(focus_asns = focus.len(), "snapshot focus filter");

    let mut days: Vec<NaiveDate> = Vec::new();
    let mut offset = 0i64;
    while offset < args.days as i64 {
        days.push(
            start_day
                .checked_add_signed(Duration::days(offset))
                .context("date overflow")?,
        );
        offset += args.step_days as i64;
    }
    // Always include the last day of the window if not already sampled.
    let last = start_day
        .checked_add_signed(Duration::days(args.days as i64 - 1))
        .context("date overflow")?;
    if days.last().copied() != Some(last) {
        days.push(last);
    }

    // Build or load snapshots for each sampled day.
    let mut paths: Vec<(NaiveDate, PathBuf)> = Vec::new();
    for day in &days {
        let path = snap_dir.join(format!("rib-{day}.json"));
        if path.exists() && args.skip_fetch {
            info!(%day, path = %path.display(), "reusing snapshot");
            paths.push((*day, path));
            continue;
        } else if path.exists() && !args.skip_fetch {
            // Re-fetch unless skip_fetch; still allow resume if file present to save time.
            info!(%day, path = %path.display(), "snapshot exists; reusing (pass fresh delete to refetch)");
            paths.push((*day, path));
            continue;
        }

        // RouteViews occasionally lacks a RIB on the exact sample day — try nearby days.
        let mut snap_ok = None;
        let mut used_day = *day;
        for delta in [0i64, -1, 1, -2, 2, -3, 3] {
            let try_day = match day.checked_add_signed(Duration::days(delta)) {
                Some(d) => d,
                None => continue,
            };
            let start = format!("{try_day}T00:00:00Z");
            let end = format!("{try_day}T00:30:00Z");
            info!(%day, %try_day, delta, "fetching RIB snapshot");
            match build_snapshot(
                &start,
                &end,
                &args.collector,
                SnapshotMode::Rib,
                false,
                None,
            ) {
                Ok(mut snap) => {
                    if !focus.is_empty() {
                        let before = snap.prefixes.len();
                        filter_snapshot_focus(&mut snap, &focus);
                        info!(
                            kept = snap.prefixes.len(),
                            dropped = before.saturating_sub(snap.prefixes.len()),
                            "applied focus ASN filter"
                        );
                    }
                    snap_ok = Some(snap);
                    used_day = try_day;
                    break;
                }
                Err(e) => {
                    warn!(%try_day, error = %e, "RIB fetch failed; trying adjacent day");
                }
            }
        }
        let Some(snap) = snap_ok else {
            anyhow::bail!("no RIB snapshot available near {day} (±3 days)");
        };
        // Always store under the planned sample day name so resume paths stay stable.
        snap.save_json(&path)?;
        info!(
            planned = %day,
            used = %used_day,
            path = %path.display(),
            prefixes = snap.prefixes.len(),
            as_of = %snap.as_of,
            "wrote day snapshot"
        );
        paths.push((*day, path));
    }

    // Consecutive diffs between sampled days.
    let mut all_events: Vec<MaEvent> = Vec::new();
    for w in paths.windows(2) {
        let (day_a, path_a) = &w[0];
        let (day_b, path_b) = &w[1];
        let before = RibSnapshot::load_json(path_a)?;
        let after = RibSnapshot::load_json(path_b)?;
        let events = diff_snapshots(&before, &after, &org_map, &glue, &cfg);
        let out = events_dir.join(format!("events-{day_a}-to-{day_b}.jsonl"));
        write_ma_events_jsonl(&out, &events)?;
        info!(
            before = %day_a,
            after = %day_b,
            events = events.len(),
            path = %out.display(),
            "day diff complete"
        );
        all_events.extend(events);
    }

    let all_path = events_dir.join("all-events.jsonl");
    write_ma_events_jsonl(&all_path, &all_events)?;

    let features = aggregate_pair_features(&all_events);
    let feat_path = args.out_dir.join("pair-features.jsonl");
    write_pair_features_jsonl(&feat_path, &features)?;
    info!(
        pairs = features.len(),
        path = %feat_path.display(),
        "wrote pair features"
    );

    // Eval wiring (empty cases → no-op success).
    if args.cases.exists() {
        let cases = load_eval_cases(&args.cases)?;
        // Score only cases overlapping this backtest window.
        let win_start = days
            .first()
            .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc())
            .unwrap();
        let win_end = days
            .last()
            .map(|d| d.and_hms_opt(23, 59, 59).unwrap().and_utc())
            .unwrap();
        let scoped: Vec<_> = cases
            .into_iter()
            .filter(|c| c.window_end >= win_start && c.window_start <= win_end)
            .collect();
        if !scoped.is_empty() {
            let report = score_backtest(&scoped, &all_events, &features);
            let report_path = args.out_dir.join("eval-report.json");
            let file = File::create(&report_path)
                .with_context(|| format!("creating {}", report_path.display()))?;
            serde_json::to_writer_pretty(BufWriter::new(file), &report)?;
            let lead_lag = build_lead_lag_rows(&scoped, &features, &all_events);
            let ll_path = args.out_dir.join("lead-lag-summary.json");
            let ll_file =
                File::create(&ll_path).with_context(|| format!("creating {}", ll_path.display()))?;
            serde_json::to_writer_pretty(BufWriter::new(ll_file), &lead_lag)?;
            info!(
                path = %report_path.display(),
                event_passed = report.event_passed,
                event_failed = report.event_failed,
                feature_passed = report.feature_passed,
                feature_failed = report.feature_failed,
                "backtest eval report"
            );
            for r in &report.feature_results {
                if r.passed {
                    info!(id = %r.id, hit = r.hit, detail = ?r.matched_detail, "FEATURE PASS");
                } else {
                    warn!(id = %r.id, hit = r.hit, "FEATURE FAIL");
                }
            }
            // Do not hard-fail the backtest on label misses — lead-lag study needs the corpus.
            if report.feature_failed > 0 {
                warn!(
                    failed = report.feature_failed,
                    total = scoped.len(),
                    "some cases failed at pair-feature level (see lead-lag-summary.json)"
                );
            }
        } else {
            info!("no eval cases overlap this backtest window; skipping label score");
        }
    }

    info!(
        samples = days.len(),
        step_days = args.step_days,
        diffs = paths.len().saturating_sub(1),
        events = all_events.len(),
        pairs = features.len(),
        "backtest complete"
    );
    Ok(())
}

fn run_daily(args: DailyArgs) -> Result<()> {
    let day = match &args.date {
        Some(s) => parse_ymd(s)?,
        None => Utc::now().date_naive(),
    };
    let snap_dir = args.state_dir.join("snapshots");
    let events_dir = args.state_dir.join("events");
    let signals_dir = args.state_dir.join("signals");
    let state_path = args.state_dir.join("pair-state.json");
    std::fs::create_dir_all(&snap_dir)?;
    std::fs::create_dir_all(&events_dir)?;
    std::fs::create_dir_all(&signals_dir)?;

    let org_map = load_org_map(&args.org_map, None, args.org_map_overlay.as_ref())?;
    let glue = load_glue(args.glue.as_ref())?;

    let mut focus: std::collections::HashSet<u32> = std::collections::HashSet::new();
    if args.focus_from_org_map {
        focus.extend(org_map.subject_asns(&glue, &SubjectHeuristics::default()));
        info!(focus_asns = focus.len(), "focus from org-map subjects");
    }
    if let Some(raw) = &args.focus_asns {
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            focus.insert(
                part.parse()
                    .with_context(|| format!("invalid --focus-asns entry `{part}`"))?,
            );
        }
        info!(focus_asns = focus.len(), "merged --focus-asns");
    }

    let today_path = snap_dir.join(format!("rib-{day}.json"));
    if !today_path.exists() {
        let start = format!("{day}T00:00:00Z");
        let end = format!("{day}T00:30:00Z");
        let mut snap = build_snapshot(
            &start,
            &end,
            &args.collector,
            SnapshotMode::Rib,
            false,
            None,
        )?;
        if !focus.is_empty() {
            let before_n = snap.prefixes.len();
            filter_snapshot_focus(&mut snap, &focus);
            info!(
                kept = snap.prefixes.len(),
                dropped = before_n.saturating_sub(snap.prefixes.len()),
                "applied focus ASN filter to today snapshot"
            );
        }
        snap.save_json(&today_path)?;
        info!(
            path = %today_path.display(),
            prefixes = snap.prefixes.len(),
            as_of = %snap.as_of,
            "wrote today snapshot"
        );
    } else {
        info!(path = %today_path.display(), "reusing today snapshot");
    }

    let prior_path = find_prior_snapshot(&snap_dir, day)?;
    let Some(prior_path) = prior_path else {
        info!(
            %day,
            "no prior snapshot in state dir; retained today only (run again tomorrow for a diff)"
        );
        prune_snapshots(&snap_dir, day, args.retain_days)?;
        return Ok(());
    };

    let mut before = RibSnapshot::load_json(&prior_path)?;
    let mut after = RibSnapshot::load_json(&today_path)?;
    // Re-apply focus if snapshots were written unfocused earlier.
    if !focus.is_empty() {
        filter_snapshot_focus(&mut before, &focus);
        filter_snapshot_focus(&mut after, &focus);
    }

    let cfg = DiffConfig {
        heuristics: SubjectHeuristics::default(),
        footprint_rel_threshold: args.footprint_rel_threshold,
        footprint_abs_threshold: args.footprint_abs_threshold,
    };
    let events = diff_snapshots(&before, &after, &org_map, &glue, &cfg);
    let full_path = events_dir.join(format!("events-{day}-full.jsonl"));
    write_ma_events_jsonl(&full_path, &events)?;

    let sparse_cfg = SparseConfig {
        min_prefix_moves_per_pair_day: args.min_prefix_moves,
        keep_new_adj: args.full,
        keep_upstream_converge: args.full,
        keep_footprint_step: args.full,
    };
    let sparse = if args.full {
        events.clone()
    } else {
        filter_sparse_events(&events, &sparse_cfg)
    };
    let sparse_path = events_dir.join(format!("events-{day}.jsonl"));
    write_ma_events_jsonl(&sparse_path, &sparse)?;

    let features = aggregate_pair_features(&sparse);
    let feat_path = events_dir.join(format!("pair-features-{day}.jsonl"));
    write_pair_features_jsonl(&feat_path, &features)?;

    let leasing = leasing_set(&[]);
    let (cleaned, dropped) = if args.no_clean {
        (features.clone(), Vec::new())
    } else {
        filter_clean_features(&features, &leasing)
    };
    let cleaned_path = events_dir.join(format!("pair-features-{day}.cleaned.jsonl"));
    write_pair_features_jsonl(&cleaned_path, &cleaned)?;

    let mut pair_state = PairStateStore::load(&state_path)?;
    pair_state.merge_day(&cleaned, after.as_of, args.pair_state_days);
    pair_state.save(&state_path)?;

    let signals = build_signals(
        &cleaned,
        &org_map,
        after.as_of,
        before.as_of,
        Some(&pair_state),
    );
    let signals_path = signals_dir.join(format!("signals-{day}.jsonl"));
    write_signals_jsonl(&signals_path, &signals)?;
    if !args.no_inbox {
        append_inbox_jsonl(signals_dir.join("inbox.jsonl"), &signals)?;
    }

    info!(
        %day,
        full_events = events.len(),
        sparse_events = sparse.len(),
        pairs = features.len(),
        cleaned_pairs = cleaned.len(),
        dropped_clean = dropped.len(),
        signals = signals.len(),
        prior = %prior_path.display(),
        signals_path = %signals_path.display(),
        "daily network-contact signals complete"
    );

    prune_snapshots(&snap_dir, day, args.retain_days)?;
    Ok(())
}

fn run_eval(args: EvalArgs) -> Result<()> {
    let cases = load_eval_cases(&args.cases)?;
    if cases.is_empty() {
        info!("no eval cases; nothing to score");
        return Ok(());
    }
    if args.events.is_none() && args.features.is_none() {
        anyhow::bail!("provide --events and/or --features");
    }

    let mut any_fail = false;
    if let Some(ev_path) = &args.events {
        let events = load_ma_events(ev_path)?;
        let results = eval_cases(&cases, &events);
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = results.len().saturating_sub(passed);
        info!(cases = results.len(), passed, failed, "event-level eval");
        for r in &results {
            if r.passed {
                info!(id = %r.id, hit = r.hit, detail = ?r.matched_detail, "PASS");
            } else {
                warn!(id = %r.id, hit = r.hit, "FAIL");
                any_fail = true;
            }
        }
        if let Some(out) = &args.output {
            write_eval_results(out, &results)?;
        }
    }
    if let Some(feat_path) = &args.features {
        let text = std::fs::read_to_string(feat_path)
            .with_context(|| format!("reading {}", feat_path.display()))?;
        let mut features = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            features.push(serde_json::from_str::<AsnPairFeature>(line).with_context(|| {
                format!("parsing feature at {}:{}", feat_path.display(), i + 1)
            })?);
        }
        let results = eval_cases_against_features(&cases, &features);
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = results.len().saturating_sub(passed);
        info!(cases = results.len(), passed, failed, "feature-level eval");
        for r in &results {
            if r.passed {
                info!(id = %r.id, hit = r.hit, detail = ?r.matched_detail, "FEATURE PASS");
            } else {
                warn!(id = %r.id, hit = r.hit, "FEATURE FAIL");
                any_fail = true;
            }
        }
    }
    if any_fail {
        anyhow::bail!("one or more eval cases failed expect_hit");
    }
    Ok(())
}

fn build_snapshot(
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
            ingest_into_rib(
                &query,
                &mut rib,
                skip_rib,
                max_updates,
                &mut updates_seen,
            )?;
            "updates"
        }
    };

    let mut snap = RibSnapshot::from_rib(&rib, as_of);
    snap.ts_start = Some(ts_start_dt);
    snap.collector = Some(collector.to_string());
    snap.source = Some(source.into());
    info!(prefixes = snap.prefixes.len(), updates = updates_seen, "snapshot built");
    Ok(snap)
}

fn load_org_map(
    path: &PathBuf,
    extra: Option<&PathBuf>,
    overlay: Option<&PathBuf>,
) -> Result<OrgMap> {
    let mut org_map = OrgMap::from_json_file(path)?;
    if let Some(overlay) = overlay {
        let overlay_map = OrgMap::from_json_file(overlay)?;
        let n = overlay_map.len();
        for org in overlay_map.orgs() {
            org_map.insert(org.clone());
        }
        info!(overlay = %overlay.display(), orgs = n, "merged org-map overlay");
    }
    if let Some(extra) = extra {
        org_map.enrich_domains_from_watchlist(extra)?;
    }
    Ok(org_map)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeadLagRow {
    id: String,
    expect_hit: bool,
    expect_kind: String,
    asn_a: u32,
    asn_b: Option<u32>,
    announce_end: String,
    feature_hit: bool,
    event_hit: bool,
    /// True if any of prefix_move / new_adj / upstream_converge for the labeled pair in-window.
    pair_contact_hit: bool,
    /// True if target ASN (asn_b, else asn_a) had a footprint_step in-window.
    target_footprint_hit: bool,
    passed_feature: bool,
    lead_days: Option<i64>,
    /// Histogram bucket: >365 | 181-365 | 91-180 | 31-90 | 8-30 | 1-7 | 0 | miss
    horizon_bucket: String,
    first_seen: Option<String>,
    detail: Option<String>,
}

fn horizon_bucket(lead_days: Option<i64>, contact: bool) -> String {
    if !contact {
        return "miss".to_string();
    }
    match lead_days {
        None => "miss".to_string(),
        Some(d) if d > 365 => ">365".to_string(),
        Some(d) if d >= 181 => "181-365".to_string(),
        Some(d) if d >= 91 => "91-180".to_string(),
        Some(d) if d >= 31 => "31-90".to_string(),
        Some(d) if d >= 8 => "8-30".to_string(),
        Some(d) if d >= 1 => "1-7".to_string(),
        Some(0) => "0".to_string(),
        // Contact after announce day (post-announce window).
        Some(_) => "post-announce".to_string(),
    }
}

/// Announce calendar day: prefer `announce=YYYY-MM-DD` in notes; else window_end.
fn announce_day(case: &EvalCase) -> chrono::NaiveDate {
    for part in case.notes.split_whitespace() {
        if let Some(raw) = part.strip_prefix("announce=") {
            if let Ok(d) = chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
                return d;
            }
        }
    }
    case.window_end.date_naive()
}

fn pair_contact_in_window(case: &EvalCase, features: &[AsnPairFeature], events: &[MaEvent]) -> (bool, Option<i64>, Option<String>) {
    let Some(b) = case.asn_b else {
        return (false, None, None);
    };
    let announce = announce_day(case);
    let (lo, hi) = canon_pair(case.asn_a, b);
    let mut first: Option<DateTime<Utc>> = None;

    if let Some(f) = features.iter().find(|f| f.asn_lo == lo && f.asn_hi == hi) {
        let overlaps = !(f.last_seen < case.window_start || f.first_seen > case.window_end);
        let contact = overlaps
            && (f.prefix_move_days > 0 || f.new_adj_days > 0 || f.upstream_converge_days > 0);
        if contact {
            // Clamp first_seen into window for lead calculation.
            let fs = if f.first_seen < case.window_start {
                case.window_start
            } else {
                f.first_seen
            };
            first = Some(fs);
        }
    }

    for ev in events {
        if ev.timestamp < case.window_start || ev.timestamp > case.window_end {
            continue;
        }
        let kind_ok = matches!(
            ev.kind,
            MaEventKind::PrefixMove | MaEventKind::NewAdj | MaEventKind::UpstreamConverge
        );
        if !kind_ok {
            continue;
        }
        if !matches!(
            (ev.asn_a, ev.asn_b),
            (Some(a), Some(bb)) if (a == case.asn_a && bb == b) || (a == b && bb == case.asn_a)
        ) {
            continue;
        }
        first = Some(match first {
            Some(prev) if prev <= ev.timestamp => prev,
            _ => ev.timestamp,
        });
    }

    match first {
        Some(fs) => {
            let lead = (announce - fs.date_naive()).num_days();
            (true, Some(lead), Some(fs.to_rfc3339()))
        }
        None => (false, None, None),
    }
}

fn target_footprint_hit(case: &EvalCase, events: &[MaEvent]) -> bool {
    let target = case.asn_b.unwrap_or(case.asn_a);
    events.iter().any(|ev| {
        ev.kind == MaEventKind::FootprintStep
            && ev.timestamp >= case.window_start
            && ev.timestamp <= case.window_end
            && ev.asn_a == Some(target)
    })
}

fn build_lead_lag_rows(
    cases: &[EvalCase],
    features: &[AsnPairFeature],
    events: &[MaEvent],
) -> Vec<LeadLagRow> {
    let feat_results = eval_cases_against_features(cases, features);
    let event_results = eval_cases(cases, events);
    cases
        .iter()
        .zip(feat_results.iter())
        .zip(event_results.iter())
        .map(|((case, fr), er)| {
            let (pair_contact_hit, lead_days, first_seen) =
                pair_contact_in_window(case, features, events);
            let target_fp = target_footprint_hit(case, events);
            let kind = serde_json::to_value(case.expect_kind)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| format!("{:?}", case.expect_kind));
            LeadLagRow {
                id: case.id.clone(),
                expect_hit: case.expect_hit,
                expect_kind: kind,
                asn_a: case.asn_a,
                asn_b: case.asn_b,
                announce_end: case.window_end.to_rfc3339(),
                feature_hit: fr.hit,
                event_hit: er.hit,
                pair_contact_hit,
                target_footprint_hit: target_fp,
                passed_feature: fr.passed,
                lead_days,
                horizon_bucket: horizon_bucket(lead_days, pair_contact_hit),
                first_seen,
                detail: fr.matched_detail.clone(),
            }
        })
        .collect()
}

fn filter_snapshot_focus(snap: &mut RibSnapshot, focus: &std::collections::HashSet<u32>) {
    snap.prefixes.retain(|_, obs| {
        focus.contains(&obs.origin_asn) || obs.as_path.iter().any(|a| focus.contains(a))
    });
}

fn load_glue(glue: Option<&PathBuf>) -> Result<GlueSet> {
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

fn parse_ymd(raw: &str) -> Result<NaiveDate> {
    NaiveDate::parse_from_str(raw, "%Y-%m-%d")
        .with_context(|| format!("parsing date `{raw}` (expected YYYY-MM-DD)"))
}

fn find_prior_snapshot(snap_dir: &std::path::Path, day: NaiveDate) -> Result<Option<PathBuf>> {
    let mut best: Option<(NaiveDate, PathBuf)> = None;
    if !snap_dir.exists() {
        return Ok(None);
    }
    for ent in std::fs::read_dir(snap_dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix("rib-").and_then(|s| s.strip_suffix(".json")) else {
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

fn prune_snapshots(snap_dir: &std::path::Path, as_of_day: NaiveDate, retain_days: u32) -> Result<()> {
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
        let Some(rest) = name.strip_prefix("rib-").and_then(|s| s.strip_suffix(".json")) else {
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

fn write_eval_results(path: &PathBuf, results: &[EvalCaseResult]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = BufWriter::new(file);
    for r in results {
        serde_json::to_writer(&mut w, r)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

fn ingest_into_rib(
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

fn apply_updates_only(
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

fn apply_elem_rib_only(rib: &mut Rib, elem: &BgpElem) {
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
    let path_id = rib.interner.intern_as_path(&as_path);
    rib.announce(
        prefix,
        RouteEntry {
            origin_asn,
            as_path_id: path_id,
            peer_asn,
            communities_id: None,
            rpki: RpkiState::Unknown,
            timestamp: elem.timestamp,
        },
    );
}

// --- optional cyber analyze path (demoted) ---

fn run_analyze(args: AnalyzeArgs) -> Result<()> {
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

    info!(alerts = alerts.len(), updates = updates_seen, "cyber analysis complete");
    match args.format {
        OutputFormat::Jsonl => write_alert_jsonl(&args.output, &alerts)?,
        OutputFormat::Parquet => write_alert_parquet(&args.output, &alerts)?,
    }
    Ok(())
}

fn cyber_updates_only(
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

fn apply_elem_cyber(
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
            rpki,
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

fn normalize_ts(raw: &str) -> Result<String> {
    if raw.chars().all(|c| c.is_ascii_digit()) {
        return Ok(raw.to_string());
    }
    let dt = DateTime::parse_from_rfc3339(raw)
        .with_context(|| format!("parsing timestamp `{raw}`"))?
        .with_timezone(&Utc);
    Ok(dt.timestamp().to_string())
}

/// Parse CLI window bounds into UTC (RFC3339 or unix seconds).
fn parse_window_instant(raw: &str) -> Result<DateTime<Utc>> {
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

fn f64_to_datetime(ts: f64) -> DateTime<Utc> {
    let secs = ts.floor() as i64;
    let nsecs = ((ts - secs as f64) * 1_000_000_000.0) as u32;
    Utc.timestamp_opt(secs, nsecs)
        .single()
        .unwrap_or_else(|| {
            Utc.timestamp_opt(secs, 0)
                .single()
                .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        })
}

fn write_alert_jsonl(path: &PathBuf, alerts: &[Alert]) -> Result<()> {
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = BufWriter::new(file);
    for alert in alerts {
        serde_json::to_writer(&mut w, alert)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

fn write_alert_parquet(path: &PathBuf, alerts: &[Alert]) -> Result<()> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("timestamp", DataType::Utf8, false),
        Field::new("prefix", DataType::Utf8, false),
        Field::new("origin_asn", DataType::UInt32, true),
        Field::new(
            "as_path",
            DataType::List(Arc::new(Field::new("item", DataType::UInt32, true))),
            false,
        ),
        Field::new("peer_asn", DataType::UInt32, false),
        Field::new("collector", DataType::Utf8, true),
        Field::new("rpki_state", DataType::Utf8, false),
        Field::new("path_verdict", DataType::Utf8, false),
        Field::new("leak_suspected", DataType::Boolean, false),
        Field::new("reason", DataType::Utf8, false),
    ]));

    let timestamps: StringArray = alerts
        .iter()
        .map(|a| Some(a.timestamp.to_rfc3339()))
        .collect();
    let prefixes: StringArray = alerts.iter().map(|a| Some(a.prefix.as_str())).collect();
    let origins: UInt32Array = alerts.iter().map(|a| a.origin_asn).collect();
    let peer_asns: UInt32Array = alerts.iter().map(|a| Some(a.peer_asn)).collect();
    let collectors: StringArray = alerts.iter().map(|a| a.collector.as_deref()).collect();
    let rpki: StringArray = alerts
        .iter()
        .map(|a| Some(a.rpki_state.to_string()))
        .collect();
    let verdicts: StringArray = alerts
        .iter()
        .map(|a| {
            Some(match a.path_verdict {
                PathVerdict::ValleyFree => "valley_free",
                PathVerdict::LeakSuspected => "leak_suspected",
                PathVerdict::Incomplete => "incomplete",
                PathVerdict::TooShort => "too_short",
            })
        })
        .collect();
    let leaks: BooleanArray = alerts.iter().map(|a| Some(a.leak_suspected)).collect();
    let reasons: StringArray = alerts.iter().map(|a| Some(a.reason.as_str())).collect();
    let as_paths = ListArray::from_iter_primitive::<arrow_array::types::UInt32Type, _, _>(
        alerts
            .iter()
            .map(|a| Some(a.as_path.iter().map(|x| Some(*x)).collect::<Vec<_>>())),
    );

    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(timestamps) as ArrayRef,
            Arc::new(prefixes),
            Arc::new(origins),
            Arc::new(as_paths),
            Arc::new(peer_asns),
            Arc::new(collectors),
            Arc::new(rpki),
            Arc::new(verdicts),
            Arc::new(leaks),
            Arc::new(reasons),
        ],
    )?;

    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let props = WriterProperties::builder()
        .set_compression(Compression::ZSTD(Default::default()))
        .build();
    let mut writer = ArrowWriter::try_new(file, schema, Some(props))?;
    writer.write(&batch)?;
    writer.close()?;
    Ok(())
}
