//! The destruction pipeline: target collection, phase ordering, sequential vs
//! batch execution, and the `--no-stop` loop.

use crate::cli::{Cli, Order};
use crate::overwrite::{self, FileId, Fill};
use crate::progress::Progress;
use crate::source::ByteSource;
use crate::{crypto, fswarn, signals};
use std::collections::HashSet;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// A collected file to destroy: its current path plus the identity recorded at
/// scan time, so every later open/unlink can confirm it is still the same inode
/// (see [`FileId`]).
#[derive(Clone, Debug)]
pub struct Target {
    pub path: PathBuf,
    pub id: FileId,
}

/// Outcome tallies for the whole invocation.
#[derive(Default, Debug)]
pub struct Summary {
    pub destroyed: usize,
    pub failed: usize,
}

/// Build the overwrite byte source from the optional `--source` path, printing
/// the custom-source caution (once) when a file is used. Shared by the file
/// pipeline and the free-space wipe path.
pub fn build_byte_source(source: &Option<PathBuf>) -> io::Result<ByteSource> {
    match source {
        Some(p) => {
            // Surface the caution even when --help was never read: a custom
            // source is only as unpredictable as its contents.
            eprintln!(
                "override: warning: using a custom --source ({}); \
                 a predictable source weakens the overwrite passes and is \
                 not recommended for serious security use (prefer the CSPRNG)",
                p.display()
            );
            ByteSource::from_file(p)
        }
        None => Ok(ByteSource::csprng()),
    }
}

/// Runs the pipeline according to a parsed [`Cli`].
pub struct Runner {
    cli: Cli,
    source: ByteSource,
}

impl Runner {
    pub fn new(mut cli: Cli) -> io::Result<Self> {
        if cli.prompt {
            // Read targets from stdin so their names never land in the shell
            // history (they are not passed as command-line arguments). Prompted
            // paths are appended to any given on the command line.
            let prompted = Self::read_prompted_paths(cli.verbose)?;
            cli.paths.extend(prompted);
        }
        let source = build_byte_source(&cli.source)?;
        Ok(Runner { cli, source })
    }

    /// Read target paths from stdin, one per line, until a blank line or EOF.
    ///
    /// The prompt is written to stderr so it does not interfere with piping and
    /// so a heredoc/pipe of paths (`printf '%s\n' a b | override -p`) also works
    /// non-interactively. Whitespace-only lines are treated as the terminator.
    fn read_prompted_paths(verbose: bool) -> io::Result<Vec<PathBuf>> {
        use std::io::Write;

        let mut paths = Vec::new();
        let stdin = io::stdin();
        let mut err = io::stderr();
        let interactive = io::IsTerminal::is_terminal(&stdin);

        if interactive {
            let _ = writeln!(
                err,
                "override: enter one path per line; blank line or Ctrl-D to finish"
            );
        }

        loop {
            if interactive {
                let _ = write!(err, "path> ");
                let _ = err.flush();
            }
            let mut line = String::new();
            let n = stdin.read_line(&mut line)?;
            if n == 0 {
                break; // EOF
            }
            let trimmed = line.trim_end_matches(|c| c == '\n' || c == '\r');
            if trimmed.trim().is_empty() {
                break; // blank line terminates the list
            }
            if verbose {
                let _ = writeln!(err, "override: queued {trimmed}");
            }
            paths.push(PathBuf::from(trimmed));
        }

        Ok(paths)
    }

    fn vlog(&self, args: std::fmt::Arguments) {
        if self.cli.verbose {
            println!("{args}");
        }
    }

    /// Expand the CLI paths into a concrete list of regular files to destroy,
    /// recording each one's scan-time identity ([`FileId`]) alongside its path.
    pub fn collect_targets(&self) -> (Vec<Target>, usize) {
        let mut files = Vec::new();
        let mut errors = 0;

        for path in &self.cli.paths {
            let meta = match std::fs::symlink_metadata(path) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("override: {}: {e}", path.display());
                    errors += 1;
                    continue;
                }
            };

            if meta.file_type().is_symlink() {
                eprintln!(
                    "override: {}: is a symlink; skipping (symlinks are never followed)",
                    path.display()
                );
                continue;
            }

            if meta.is_dir() {
                if !self.cli.recursive {
                    eprintln!(
                        "override: {}: is a directory (use --recursive to process it)",
                        path.display()
                    );
                    errors += 1;
                    continue;
                }
                for entry in WalkDir::new(path).follow_links(false) {
                    match entry {
                        Ok(e) if e.file_type().is_file() => match e.metadata() {
                            Ok(m) => files.push(Target {
                                id: FileId::of(&m),
                                path: e.into_path(),
                            }),
                            Err(err) => {
                                eprintln!("override: {}: {err}", e.path().display());
                                errors += 1;
                            }
                        },
                        Ok(_) => {} // directories and symlinks: skip
                        Err(e) => {
                            eprintln!("override: walk error: {e}");
                            errors += 1;
                        }
                    }
                }
            } else if meta.is_file() {
                files.push(Target {
                    id: FileId::of(&meta),
                    path: path.clone(),
                });
            } else {
                eprintln!(
                    "override: {}: not a regular file (skipping)",
                    path.display()
                );
                errors += 1;
            }
        }
        (files, errors)
    }

    // ---- individual phases ----------------------------------------------
    //
    // Each phase re-opens the target via `overwrite::open_target`, which uses
    // `O_NOFOLLOW` and re-verifies the inode against the scan-time `FileId`, so
    // a symlink/rename race between passes cannot redirect the writes.

    fn phase_encrypt(&self, target: &Target, progress: &Progress, verify: bool) -> io::Result<()> {
        let passes = self.cli.encryption;
        for pass in 1..=passes {
            let (mut file, len) = overwrite::open_target(&target.path, &target.id)?;
            crypto::encrypt_pass(&mut file, len, verify, &mut |n| progress.inc(n))?;
            self.vlog(format_args!(
                "  [encrypt] {} pass {}/{} (len {}, verify {})",
                target.path.display(),
                pass,
                passes,
                len,
                verify
            ));
            if signals::interrupted() {
                break;
            }
        }
        Ok(())
    }

    fn phase_random(
        &mut self,
        target: &Target,
        round: &str,
        progress: &Progress,
    ) -> io::Result<()> {
        let passes = self.cli.iterations;
        for pass in 1..=passes {
            let (mut file, len) = overwrite::open_target(&target.path, &target.id)?;
            overwrite::overwrite_pass(
                &mut file,
                len,
                &mut Fill::Random(&mut self.source),
                &mut |n| progress.inc(n),
            )?;
            let src = if self.source.is_file() {
                "source-file"
            } else {
                "csprng"
            };
            self.vlog(format_args!(
                "  [random {}] {} pass {}/{} ({}, len {})",
                round,
                target.path.display(),
                pass,
                passes,
                src,
                len
            ));
            if signals::interrupted() {
                break;
            }
        }
        Ok(())
    }

    fn phase_null(&self, target: &Target, progress: &Progress) -> io::Result<()> {
        let passes = self.cli.null;
        for pass in 1..=passes {
            let (mut file, len) = overwrite::open_target(&target.path, &target.id)?;
            overwrite::overwrite_pass(&mut file, len, &mut Fill::Null, &mut |n| progress.inc(n))?;
            self.vlog(format_args!(
                "  [null] {} pass {}/{} (len {})",
                target.path.display(),
                pass,
                passes,
                len
            ));
            if signals::interrupted() {
                break;
            }
        }
        Ok(())
    }

    /// Rename the file to random name(s). Returns the (possibly unchanged) path
    /// the file now lives at. With `--rename 0` this is a no-op returning the
    /// current path. The inode is unchanged by the rename, so the target's
    /// [`FileId`] stays valid at the new path.
    fn phase_rename(&self, target: &Target) -> io::Result<PathBuf> {
        if self.cli.rename > 0 {
            overwrite::rename_passes(&target.path, self.cli.rename, self.cli.verbose)
        } else {
            Ok(target.path.clone())
        }
    }

    /// Unlink the file (which must already sit at its final, possibly renamed,
    /// path) and durably persist the removal. The unlink is verified against and
    /// performed relative to the parent-directory fd inside `overwrite::delete`,
    /// which also fsyncs the directory.
    fn phase_delete(&self, path: &Path, id: &FileId) -> io::Result<()> {
        overwrite::delete(path, id)?;
        self.vlog(format_args!(
            "  [delete] unlinked {} (parent dir synced)",
            path.display()
        ));
        Ok(())
    }

    /// Rename then unlink. Returns Ok once the file no longer exists.
    fn phase_rename_delete(&self, target: &Target) -> io::Result<()> {
        let final_path = self.phase_rename(target)?;
        self.phase_delete(&final_path, &target.id)
    }

    /// The four overwrite/encrypt phases in default order, on one file.
    fn wipe_phases(&mut self, target: &Target, progress: &Progress) -> io::Result<()> {
        self.phase_encrypt(target, progress, !self.cli.no_verify)?;
        self.phase_random(target, "A", progress)?;
        self.phase_null(target, progress)?;
        self.phase_random(target, "B", progress)?;
        Ok(())
    }

    // ---- top-level drivers ---------------------------------------------

    /// Run everything according to the configured order / no-stop settings.
    pub fn run(&mut self) -> Summary {
        let (files, collect_errors) = self.collect_targets();
        let mut summary = Summary {
            destroyed: 0,
            failed: collect_errors,
        };

        // Warn once per distinct filesystem where logical overwrites may not
        // reach physical blocks (btrfs/ZFS/overlay) or are volatile (tmpfs).
        let paths: Vec<PathBuf> = files.iter().map(|t| t.path.clone()).collect();
        let mut seen_fs = HashSet::new();
        fswarn::warn_for_paths(&paths, &mut seen_fs);

        // Dry run: describe the plan for each collected file and stop. Collection
        // errors are still folded into `failed`, so a bad target still exits 1.
        if self.cli.dry_run {
            for target in &files {
                println!(
                    "would destroy: {}  [{}]",
                    target.path.display(),
                    self.pipeline_description()
                );
            }
            // Report the count of files that *would* be destroyed; collection
            // errors remain in `failed` so a bad target still exits 1.
            summary.destroyed = files.len();
            return summary;
        }

        if files.is_empty() {
            return summary;
        }

        // Determinate byte progress bar when running interactively (see
        // `progress_enabled`); a no-op handle otherwise.
        let progress = if self.progress_enabled() {
            Progress::bar(self.total_bytes(&files), true)
        } else {
            Progress::hidden()
        };

        if self.cli.no_stop {
            self.run_no_stop(&files, &mut summary, &progress);
        } else if self.cli.resolved_order() == Order::Batch {
            self.run_batch(&files, &mut summary, &progress);
        } else {
            self.run_sequential(&files, &mut summary, &progress);
        }
        progress.finish();
        summary
    }

    /// Human-readable one-line description of the configured pipeline, used by
    /// `--dry-run`.
    fn pipeline_description(&self) -> String {
        let mut parts = Vec::new();
        if self.cli.encryption > 0 {
            parts.push(format!("encrypt×{}", self.cli.encryption));
        }
        if self.cli.iterations > 0 {
            parts.push(format!("random×{}", self.cli.iterations));
        }
        if self.cli.null > 0 {
            parts.push(format!("null×{}", self.cli.null));
        }
        if self.cli.iterations > 0 {
            parts.push(format!("random×{}", self.cli.iterations));
        }
        if self.cli.rename > 0 {
            parts.push(format!("rename×{}", self.cli.rename));
        }
        parts.push("delete".to_string());
        parts.join(" → ")
    }

    /// Whether to draw a progress bar: only on an interactive stderr, and not
    /// when verbose logging (which would clash) or in the indeterminate no-stop
    /// / dry-run modes.
    fn progress_enabled(&self) -> bool {
        io::stderr().is_terminal() && !self.cli.verbose && !self.cli.no_stop && !self.cli.dry_run
    }

    /// Total bytes the pipeline expects to write across all files. In-place
    /// passes preserve length, so each file contributes `len × pass_count`.
    fn total_bytes(&self, files: &[Target]) -> u64 {
        let per_file_passes =
            self.cli.encryption as u64 + 2 * self.cli.iterations as u64 + self.cli.null as u64;
        files
            .iter()
            .map(|t| std::fs::metadata(&t.path).map(|m| m.len()).unwrap_or(0))
            .map(|len| len.saturating_mul(per_file_passes))
            .sum()
    }

    fn run_sequential(&mut self, files: &[Target], summary: &mut Summary, progress: &Progress) {
        for target in files {
            self.vlog(format_args!("Processing {}", target.path.display()));
            let res = self
                .wipe_phases(target, progress)
                .and_then(|_| self.phase_rename_delete(target));
            match res {
                Ok(()) => summary.destroyed += 1,
                Err(e) => {
                    eprintln!("override: {}: {e}", target.path.display());
                    summary.failed += 1;
                }
            }
        }
    }

    fn run_batch(&mut self, files: &[Target], summary: &mut Summary, progress: &Progress) {
        // Track which files are still alive; drop any that error out.
        let mut alive: Vec<bool> = vec![true; files.len()];

        macro_rules! for_alive {
            ($label:expr, $body:expr) => {{
                self.vlog(format_args!("== phase: {} ==", $label));
                for (idx, target) in files.iter().enumerate() {
                    if !alive[idx] {
                        continue;
                    }
                    let f: &mut dyn FnMut(&mut Self, &Target) -> io::Result<()> = $body;
                    if let Err(e) = f(self, target) {
                        eprintln!("override: {}: {e}", target.path.display());
                        alive[idx] = false;
                        summary.failed += 1;
                    }
                }
            }};
        }

        for_alive!("encrypt", &mut |s, t| s.phase_encrypt(
            t,
            progress,
            !s.cli.no_verify
        ));
        for_alive!("random A", &mut |s, t| s.phase_random(t, "A", progress));
        for_alive!("null", &mut |s, t| s.phase_null(t, progress));
        for_alive!("random B", &mut |s, t| s.phase_random(t, "B", progress));
        for_alive!("rename+delete", &mut |s, t| s.phase_rename_delete(t));

        summary.destroyed += alive.iter().filter(|&&a| a).count();
    }

    /// The `--no-stop` driver, built for the "I can't press Ctrl-C" case.
    ///
    /// Ordering of the protections is deliberate: every target is **first**
    /// crypto-shredded and **then** renamed, so that even a hard kill (power
    /// loss, SIGKILL) that never reaches the finalize step still leaves the
    /// content unreadable and the original name gone. Only after that one-time
    /// setup does it loop random -> null -> random until interrupted, and delete
    /// on the way out. Under the default batch order the encrypt (and rename)
    /// runs across ALL files before the looping starts, so an early kill has
    /// crypto-shredded the whole set, not just the first file.
    fn run_no_stop(&mut self, files: &[Target], summary: &mut Summary, progress: &Progress) {
        let batch = self.cli.resolved_order() == Order::Batch;
        self.vlog(format_args!(
            "no-stop ({} order): encrypt+rename every target up front, then loop \
             random->null->random until interrupted (Ctrl-C once to finish, twice to abort)",
            if batch { "batch" } else { "sequential" }
        ));

        // Each target, with its CURRENT path updated once it is renamed. The
        // inode is unchanged by rename, so `target.id` stays valid throughout.
        let mut targets: Vec<Target> = files.to_vec();
        let mut alive: Vec<bool> = vec![true; targets.len()];

        // Run `body` over every still-alive target, dropping any that error out.
        macro_rules! for_alive {
            ($label:expr, $body:expr) => {{
                self.vlog(format_args!("== phase: {} ==", $label));
                for idx in 0..targets.len() {
                    if !alive[idx] {
                        continue;
                    }
                    let f: &mut dyn FnMut(&mut Self, &Target) -> io::Result<()> = $body;
                    if let Err(e) = f(self, &targets[idx]) {
                        eprintln!("override: {}: {e}", targets[idx].path.display());
                        alive[idx] = false;
                        summary.failed += 1;
                    }
                    if signals::interrupted() {
                        break;
                    }
                }
            }};
        }

        // Rename every still-alive target, recording its new path. Kept separate
        // from `for_alive!` because it mutates `targets`. A rename is quick and
        // atomic, so it runs to the end even if an interrupt has already fired.
        macro_rules! rename_all {
            () => {{
                self.vlog(format_args!("== phase: rename =="));
                for idx in 0..targets.len() {
                    if !alive[idx] {
                        continue;
                    }
                    match self.phase_rename(&targets[idx]) {
                        Ok(new_path) => targets[idx].path = new_path,
                        Err(e) => {
                            eprintln!("override: {}: {e}", targets[idx].path.display());
                            alive[idx] = false;
                            summary.failed += 1;
                        }
                    }
                }
            }};
        }

        // ---- Setup (once): lock in crypto-shred + hidden name for every file.
        // The up-front encrypt skips read-back verification (`verify = false`)
        // so this protection lands as fast as possible; the subsequent overwrite
        // loop re-covers the bytes anyway, so a rare silent bad write is not
        // relied upon here.
        if batch {
            // Crypto-shred the entire set before renaming, so the most important
            // protection covers all targets as early as possible.
            for_alive!("encrypt", &mut |s, t| s.phase_encrypt(t, progress, false));
            rename_all!();
        } else {
            // Per file: encrypt then immediately rename before the next target.
            self.vlog(format_args!("== phase: encrypt+rename (sequential) =="));
            for idx in 0..targets.len() {
                if !alive[idx] {
                    continue;
                }
                match self
                    .phase_encrypt(&targets[idx], progress, false)
                    .and_then(|_| self.phase_rename(&targets[idx]))
                {
                    Ok(new_path) => targets[idx].path = new_path,
                    Err(e) => {
                        eprintln!("override: {}: {e}", targets[idx].path.display());
                        alive[idx] = false;
                        summary.failed += 1;
                    }
                }
                if signals::interrupted() {
                    break;
                }
            }
        }

        // ---- Loop: keep overwriting with random/null/random until interrupted.
        let mut cycle: u64 = 0;
        while !signals::interrupted() {
            cycle += 1;
            self.vlog(format_args!("-- cycle {cycle} --"));
            if batch {
                for_alive!("random A", &mut |s, t| s.phase_random(t, "A", progress));
                for_alive!("null", &mut |s, t| s.phase_null(t, progress));
                for_alive!("random B", &mut |s, t| s.phase_random(t, "B", progress));
            } else {
                for idx in 0..targets.len() {
                    if !alive[idx] {
                        continue;
                    }
                    let res = self
                        .phase_random(&targets[idx], "A", progress)
                        .and_then(|_| self.phase_null(&targets[idx], progress))
                        .and_then(|_| self.phase_random(&targets[idx], "B", progress));
                    if let Err(e) = res {
                        eprintln!("override: {}: {e}", targets[idx].path.display());
                        alive[idx] = false;
                        summary.failed += 1;
                    }
                    if signals::interrupted() {
                        break;
                    }
                }
            }
        }

        // ---- Finalize: delete every surviving target (already renamed above).
        self.vlog(format_args!("interrupt received; deleting targets"));
        for idx in 0..targets.len() {
            if !alive[idx] {
                continue;
            }
            match self.phase_delete(&targets[idx].path, &targets[idx].id) {
                Ok(()) => summary.destroyed += 1,
                Err(e) => {
                    eprintln!("override: {}: {e}", targets[idx].path.display());
                    summary.failed += 1;
                }
            }
        }
    }
}
