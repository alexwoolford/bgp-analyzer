//! Library surface for the bgp-analyzer CLI (testable helpers + dispatch).

pub mod args;
pub mod commands;

use anyhow::Result;
use clap::Parser;

use args::{Cli, Commands};
use commands::{
    run_analyze, run_backtest, run_build_org_map, run_daily, run_eval, run_ma_diff, run_snapshot,
};

/// Parse argv and run the selected subcommand.
pub fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::BuildOrgMap(a) => run_build_org_map(a),
        Commands::Snapshot(a) => run_snapshot(a),
        Commands::MaDiff(a) => run_ma_diff(a),
        Commands::Backtest(a) => run_backtest(a),
        Commands::Daily(a) => run_daily(a),
        Commands::Eval(a) => run_eval(a),
        Commands::Analyze(a) => run_analyze(a),
    }
}

#[cfg(test)]
mod smoke_tests;
