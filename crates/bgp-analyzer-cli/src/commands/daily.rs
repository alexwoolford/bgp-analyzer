//! Daily network-contact emit.
use anyhow::{Context, Result};
use bgp_ma::RibSnapshot;
use bgp_ma::{
    aggregate_pair_features, append_inbox_jsonl, build_signals, diff_snapshots,
    filter_clean_features, filter_sparse_events, leasing_set, write_ma_events_jsonl,
    write_pair_features_jsonl, write_signals_jsonl, CleanContext, DiffConfig, SparseConfig,
};
use bgp_map::SubjectHeuristics;
use bgp_state::{work_db_path, SignalRun, SignalRunStatus, WorkDb};
use chrono::{DateTime, NaiveDate, Utc};
use tracing::{info, warn};

use super::common::{
    apply_org_overlay, filter_snapshot_focus, find_prior_snapshot, load_glue, parse_ymd,
    prune_snapshots,
};
use super::snapshot::build_snapshot;
use crate::args::{DailyArgs, SnapshotMode};

pub fn run_daily(args: DailyArgs) -> Result<()> {
    let started_at = Utc::now();
    let day = match &args.date {
        Some(s) => parse_ymd(s)?,
        None => Utc::now().date_naive(),
    };
    let snap_dir = args.state_dir.join("snapshots");
    let events_dir = args.state_dir.join("events");
    let signals_dir = args.state_dir.join("signals");
    std::fs::create_dir_all(&snap_dir)?;
    std::fs::create_dir_all(&events_dir)?;
    std::fs::create_dir_all(&signals_dir)?;

    let sqlite = work_db_path(&args.state_dir);
    let mut db = WorkDb::open(&sqlite)?;
    run_daily_after_open(
        &args,
        day,
        started_at,
        &mut db,
        &sqlite,
        &snap_dir,
        &events_dir,
        &signals_dir,
    )
    .inspect_err(|_| {
        if let Err(mark) = db.commit_signal_run(&SignalRun {
            as_of_date: day.to_string(),
            as_of: day
                .and_hms_opt(0, 30, 0)
                .expect("00:30:00 is a valid time")
                .and_utc(),
            prior_as_of: None,
            started_at,
            status: SignalRunStatus::Error,
            signal_count: 0,
        }) {
            warn!(error = %mark, "failed to record signal_runs status=error");
        }
    })
}

fn run_daily_after_open(
    args: &DailyArgs,
    day: NaiveDate,
    started_at: DateTime<Utc>,
    db: &mut WorkDb,
    sqlite: &std::path::Path,
    snap_dir: &std::path::Path,
    events_dir: &std::path::Path,
    signals_dir: &std::path::Path,
) -> Result<()> {
    let mut org_map = db.require_fresh_org_map(started_at, args.org_map_max_age_days)?;
    if let Some(legacy) = &args.org_map {
        apply_org_overlay(&mut org_map, legacy)?;
    }
    if let Some(overlay) = &args.org_map_overlay {
        apply_org_overlay(&mut org_map, overlay)?;
    }
    let glue = load_glue(args.glue.as_ref())?;

    let mut extra_focus: std::collections::HashSet<u32> = std::collections::HashSet::new();
    if let Some(raw) = &args.focus_asns {
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            extra_focus.insert(
                part.parse()
                    .with_context(|| format!("invalid --focus-asns entry `{part}`"))?,
            );
        }
    }

    let today_path = snap_dir.join(format!("rib-{day}.json"));
    let existed = today_path.exists();
    let mut after = if existed {
        info!(path = %today_path.display(), "reusing today snapshot");
        RibSnapshot::load_json(&today_path)?
    } else {
        let start = format!("{day}T00:00:00Z");
        let end = format!("{day}T00:30:00Z");
        build_snapshot(
            &start,
            &end,
            &args.collector,
            SnapshotMode::Rib,
            false,
            None,
        )?
    };

    let counts = after.prefix_count_by_origin();
    let mut focus = extra_focus;
    if args.focus_from_org_map {
        focus.extend(org_map.subject_asns(&glue, &SubjectHeuristics::default(), Some(&counts)));
        info!(
            focus_asns = focus.len(),
            origins = counts.len(),
            "focus from org-map subjects (RIB origin prefix counts)"
        );
    }
    if !focus.is_empty() {
        let before_n = after.prefixes.len();
        filter_snapshot_focus(&mut after, &focus);
        info!(
            kept = after.prefixes.len(),
            dropped = before_n.saturating_sub(after.prefixes.len()),
            "applied origin-only focus ASN filter to today snapshot"
        );
    }
    if !existed || !focus.is_empty() {
        after.save_json(&today_path)?;
        info!(
            path = %today_path.display(),
            prefixes = after.prefixes.len(),
            as_of = %after.as_of,
            "wrote today snapshot"
        );
    }

    let prior_path = find_prior_snapshot(snap_dir, day)?;
    let Some(prior_path) = prior_path else {
        db.commit_signal_run(&SignalRun {
            as_of_date: day.to_string(),
            as_of: after.as_of,
            prior_as_of: None,
            started_at,
            status: SignalRunStatus::SnapshotOnly,
            signal_count: 0,
        })?;
        info!(
            %day,
            sqlite = %sqlite.display(),
            "no prior snapshot in state dir; retained today only (run again tomorrow for a diff)"
        );
        prune_snapshots(snap_dir, day, args.retain_days)?;
        return Ok(());
    };

    let mut before = RibSnapshot::load_json(&prior_path)?;
    // Re-apply origin-only focus if snapshots were written unfocused earlier.
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
    if args.debug_jsonl {
        let full_path = events_dir.join(format!("events-{day}-full.jsonl"));
        write_ma_events_jsonl(&full_path, &events)?;
        let sparse_path = events_dir.join(format!("events-{day}.jsonl"));
        write_ma_events_jsonl(&sparse_path, &sparse)?;
    }

    let features = aggregate_pair_features(&sparse);
    if args.debug_jsonl {
        let feat_path = events_dir.join(format!("pair-features-{day}.jsonl"));
        write_pair_features_jsonl(&feat_path, &features)?;
    }

    let leasing = leasing_set(&[]);
    let ctx = CleanContext {
        leasing: &leasing,
        glue: &glue,
        org_map: &org_map,
    };
    let (cleaned, dropped) = if args.no_clean {
        (features.clone(), Vec::new())
    } else {
        filter_clean_features(&features, &ctx)
    };
    if args.debug_jsonl {
        let cleaned_path = events_dir.join(format!("pair-features-{day}.cleaned.jsonl"));
        write_pair_features_jsonl(&cleaned_path, &cleaned)?;
    }

    let mut pair_state = db.load_pair_state()?;
    pair_state.merge_day(&cleaned, after.as_of, args.pair_state_days);

    let signals = build_signals(
        &cleaned,
        &org_map,
        after.as_of,
        before.as_of,
        Some(&pair_state),
    );
    db.commit_daily(
        &signals,
        &pair_state,
        &SignalRun {
            as_of_date: day.to_string(),
            as_of: after.as_of,
            prior_as_of: Some(before.as_of),
            started_at,
            status: SignalRunStatus::Ok,
            signal_count: signals.len() as i64,
        },
    )?;

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
        sqlite = %sqlite.display(),
        signals_path = %signals_path.display(),
        "daily network-contact signals complete"
    );

    prune_snapshots(snap_dir, day, args.retain_days)?;
    Ok(())
}
