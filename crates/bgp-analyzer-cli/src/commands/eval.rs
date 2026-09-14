//! Eval subcommand.
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use bgp_ma::{
    eval_cases, eval_cases_against_features, load_eval_cases, load_ma_events, AsnPairFeature,
    EvalCaseResult,
};
use tracing::{info, warn};

use crate::args::EvalArgs;

pub fn run_eval(args: EvalArgs) -> Result<()> {
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
            features.push(
                serde_json::from_str::<AsnPairFeature>(line).with_context(|| {
                    format!("parsing feature at {}:{}", feat_path.display(), i + 1)
                })?,
            );
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

pub fn write_eval_results(path: &PathBuf, results: &[EvalCaseResult]) -> Result<()> {
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
