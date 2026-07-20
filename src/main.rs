//! `override` binary entry point.

use clap::Parser;
use override_tool::cli::Cli;
use override_tool::pipeline::Runner;
use override_tool::{resilience, signals};
use std::process::ExitCode;

fn main() -> ExitCode {
    // Parse first so `--help`/`--version` and bad args are handled before we
    // do anything with side effects (and so we know whether to be verbose).
    let cli = Cli::parse();

    // Self-resilience: re-exec from an in-memory copy of our own executable so
    // that deleting/overwriting the on-disk binary (including shredding it)
    // cannot affect this process. Best-effort; returns if already done or
    // unsupported. This must run before we touch any target files.
    resilience::reexec_from_memfd(cli.verbose);

    // Handle interrupts everywhere (not just --no-stop): finish the current
    // write safely, then continue to rename+delete. Second signal aborts.
    signals::install();

    let mut runner = match Runner::new(cli) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("override: {e}");
            return ExitCode::from(2);
        }
    };

    let summary = runner.run();

    println!(
        "override: {} destroyed, {} failed",
        summary.destroyed, summary.failed
    );

    if summary.failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
