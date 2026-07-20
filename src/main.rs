//! `override` binary entry point.

use clap::Parser;
use override_tool::cli::Cli;
use override_tool::pipeline::{self, Runner};
use override_tool::progress::Progress;
use override_tool::{freespace, fswarn, resilience, signals};
use std::collections::HashSet;
use std::io::IsTerminal;
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

    // Free-space wiping is a distinct mode: it scrubs a volume's unused space
    // rather than destroying named files.
    if cli.wipe_free.is_some() {
        return run_wipe_free(&cli);
    }

    let mut runner = match Runner::new(cli.clone()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("override: {e}");
            return ExitCode::from(2);
        }
    };

    let summary = runner.run();

    if cli.dry_run {
        println!(
            "override: dry run: {} file(s) would be destroyed, {} failed",
            summary.destroyed, summary.failed
        );
    } else {
        println!(
            "override: {} destroyed, {} failed",
            summary.destroyed, summary.failed
        );
    }

    if summary.failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Free-space wipe mode (`--wipe-free <DIR>`).
fn run_wipe_free(cli: &Cli) -> ExitCode {
    let dir = cli.wipe_free.as_ref().expect("wipe_free is Some");

    // Warn about CoW/volatile filesystems where free-space wiping is unreliable.
    let mut seen_fs = HashSet::new();
    fswarn::warn_for_paths(std::slice::from_ref(dir), &mut seen_fs);

    if cli.dry_run {
        println!(
            "would wipe free space of {} ({} random + {} null pass(es), then remove the fill file)",
            dir.display(),
            cli.iterations,
            cli.null
        );
        return ExitCode::SUCCESS;
    }

    let mut source = match pipeline::build_byte_source(&cli.source) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("override: {e}");
            return ExitCode::from(2);
        }
    };

    eprintln!(
        "override: wiping free space of {} -- this temporarily fills the volume to 100%",
        dir.display()
    );

    // A byte spinner while filling (indeterminate total), unless verbose or
    // non-interactive.
    let show = std::io::stderr().is_terminal() && !cli.verbose;
    let progress = Progress::spinner("wiping free space", show);

    let result = freespace::wipe_free(
        dir,
        cli.iterations,
        cli.null,
        &mut source,
        cli.verbose,
        &progress,
        None,
    );
    progress.finish();

    match result {
        Ok(()) => {
            println!("override: free-space wipe of {} complete", dir.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("override: {}: {e}", dir.display());
            ExitCode::from(1)
        }
    }
}
