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

    // Process hardening: keep the key/plaintext buffers out of a same-user core
    // dump / ptrace / /proc/<pid>/mem for the life of this run (audit L-2). Must
    // run AFTER the re-exec, since execve resets the dumpable flag.
    harden_process();

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

    // C-1: on a filesystem where in-place writes may be redirected (CoW/SSD) or
    // are remote (network), a "destroyed" count is NOT a promise the data is
    // unrecoverable. Never let the success line stand unqualified in that case.
    if summary.unassured_fs > 0 && summary.destroyed > 0 {
        eprintln!(
            "override: caution: {} of the targeted filesystem(s) may retain the original \
             physical blocks (see the warning above); \"destroyed\" here does NOT mean the \
             data is unrecoverable. Use full-disk encryption, ATA/NVMe secure-erase, or \
             physical destruction for real assurance.",
            summary.unassured_fs
        );
    }

    if summary.failed > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Best-effort process hardening: mark this process non-dumpable so its ChaCha20
/// key and plaintext chunks cannot be captured by a same-user core dump (e.g.
/// after a `panic = "abort"` SIGABRT), `ptrace`, or `/proc/<pid>/mem` while it
/// runs (audit L-2). `PR_SET_DUMPABLE(0)` also flips /proc/<pid> ownership to
/// root, which blocks same-UID ptrace attaches. This is defense-in-depth, not a
/// guarantee, and a failure is ignored. Off Linux it is a no-op.
#[cfg(target_os = "linux")]
fn harden_process() {
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) passes no pointers and only affects this
    // process's own dumpable flag.
    unsafe {
        let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }
}

#[cfg(not(target_os = "linux"))]
fn harden_process() {}

/// Whether `dir` lives on the same filesystem as `/` (compared by device id).
/// Best-effort: if either stat fails we return `false` (do not block), since the
/// guard exists to prevent an obvious foot-gun, not to be a hard security
/// boundary. A separately-mounted volume (its own `st_dev`) is not flagged.
#[cfg(unix)]
fn same_fs_as_root(dir: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(dir), std::fs::metadata("/")) {
        (Ok(a), Ok(b)) => a.dev() == b.dev(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_fs_as_root(_dir: &std::path::Path) -> bool {
    false
}

/// Free-space wipe mode (`--wipe-free <DIR>`).
fn run_wipe_free(cli: &Cli) -> ExitCode {
    let dir = cli.wipe_free.as_ref().expect("wipe_free is Some");

    // Warn about CoW/volatile filesystems where free-space wiping is unreliable.
    let mut seen_fs = HashSet::new();
    let unassured = fswarn::warn_for_paths(std::slice::from_ref(dir), &mut seen_fs);
    if unassured > 0 {
        eprintln!(
            "override: caution: {} is on a filesystem where overwrites may not reach the \
             original physical blocks; free-space wiping cannot be assured effective here.",
            dir.display()
        );
    }

    if cli.dry_run {
        println!(
            "would wipe free space of {} ({} random + {} null pass(es), then remove the fill file)",
            dir.display(),
            cli.iterations,
            cli.null
        );
        return ExitCode::SUCCESS;
    }

    // Guard: filling the root/system filesystem to 100% can crash services or the
    // whole machine (audit L-3). Refuse unless the user explicitly opts in.
    if !cli.force && same_fs_as_root(dir) {
        eprintln!(
            "override: refusing to wipe free space of {}: it is on the root/system \
             filesystem, and filling it to 100% can crash running services or the system. \
             Re-run with --force if you are certain this volume is safe to fill.",
            dir.display()
        );
        return ExitCode::from(2);
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
