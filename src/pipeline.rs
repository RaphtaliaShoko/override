//! The destruction pipeline: target collection, phase ordering, sequential vs
//! batch execution, and the `--no-stop` loop.

use crate::cli::{Cli, Order};
use crate::overwrite::{self, Fill};
use crate::source::ByteSource;
use crate::{crypto, signals};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Outcome tallies for the whole invocation.
#[derive(Default, Debug)]
pub struct Summary {
    pub destroyed: usize,
    pub failed: usize,
}

/// Runs the pipeline according to a parsed [`Cli`].
pub struct Runner {
    cli: Cli,
    source: ByteSource,
}

impl Runner {
    pub fn new(cli: Cli) -> io::Result<Self> {
        let source = match &cli.source {
            Some(p) => ByteSource::from_file(p)?,
            None => ByteSource::csprng(),
        };
        Ok(Runner { cli, source })
    }

    fn vlog(&self, args: std::fmt::Arguments) {
        if self.cli.verbose {
            println!("{args}");
        }
    }

    /// Expand the CLI paths into a concrete list of regular files to destroy.
    pub fn collect_targets(&self) -> (Vec<PathBuf>, usize) {
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
                        Ok(e) if e.file_type().is_file() => files.push(e.into_path()),
                        Ok(_) => {} // directories and symlinks: skip
                        Err(e) => {
                            eprintln!("override: walk error: {e}");
                            errors += 1;
                        }
                    }
                }
            } else if meta.is_file() {
                files.push(path.clone());
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

    fn open_rw(path: &Path) -> io::Result<(File, u64)> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        Ok((file, len))
    }

    // ---- individual phases (operate on a stable path) -------------------

    fn phase_encrypt(&self, path: &Path) -> io::Result<()> {
        let passes = self.cli.encryption;
        for pass in 1..=passes {
            let (mut file, len) = Self::open_rw(path)?;
            crypto::encrypt_pass(&mut file, len)?;
            self.vlog(format_args!(
                "  [encrypt] {} pass {}/{} (len {})",
                path.display(),
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

    fn phase_random(&mut self, path: &Path, round: &str) -> io::Result<()> {
        let passes = self.cli.iterations;
        for pass in 1..=passes {
            let (mut file, len) = Self::open_rw(path)?;
            overwrite::overwrite_pass(&mut file, len, &mut Fill::Random(&mut self.source))?;
            let src = if self.source.is_file() { "source-file" } else { "csprng" };
            self.vlog(format_args!(
                "  [random {}] {} pass {}/{} ({}, len {})",
                round,
                path.display(),
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

    fn phase_null(&self, path: &Path) -> io::Result<()> {
        let passes = self.cli.null;
        for pass in 1..=passes {
            let (mut file, len) = Self::open_rw(path)?;
            overwrite::overwrite_pass(&mut file, len, &mut Fill::Null)?;
            self.vlog(format_args!(
                "  [null] {} pass {}/{} (len {})",
                path.display(),
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

    /// Rename then unlink. Returns Ok once the file no longer exists.
    fn phase_rename_delete(&self, path: &Path) -> io::Result<()> {
        let final_path = if self.cli.rename > 0 {
            overwrite::rename_passes(path, self.cli.rename, self.cli.verbose)?
        } else {
            path.to_path_buf()
        };
        overwrite::delete(&final_path)?;
        self.vlog(format_args!("  [delete] unlinked {}", final_path.display()));
        Ok(())
    }

    /// The four overwrite/encrypt phases in default order, on one file.
    fn wipe_phases(&mut self, path: &Path) -> io::Result<()> {
        self.phase_encrypt(path)?;
        self.phase_random(path, "A")?;
        self.phase_null(path)?;
        self.phase_random(path, "B")?;
        Ok(())
    }

    // ---- top-level drivers ---------------------------------------------

    /// Run everything according to the configured order / no-stop settings.
    pub fn run(&mut self) -> Summary {
        let (files, mut collect_errors) = self.collect_targets();
        let mut summary = Summary::default();
        summary.failed += collect_errors;
        // (collect_errors folded in; keep variable to avoid clippy noise)
        collect_errors = 0;
        let _ = collect_errors;

        if files.is_empty() {
            return summary;
        }

        if self.cli.no_stop {
            self.run_no_stop(&files, &mut summary);
        } else if self.cli.order == Order::Batch {
            self.run_batch(&files, &mut summary);
        } else {
            self.run_sequential(&files, &mut summary);
        }
        summary
    }

    fn run_sequential(&mut self, files: &[PathBuf], summary: &mut Summary) {
        for path in files {
            self.vlog(format_args!("Processing {}", path.display()));
            let res = self
                .wipe_phases(path)
                .and_then(|_| self.phase_rename_delete(path));
            match res {
                Ok(()) => summary.destroyed += 1,
                Err(e) => {
                    eprintln!("override: {}: {e}", path.display());
                    summary.failed += 1;
                }
            }
        }
    }

    fn run_batch(&mut self, files: &[PathBuf], summary: &mut Summary) {
        // Track which files are still alive; drop any that error out.
        let mut alive: Vec<bool> = vec![true; files.len()];

        macro_rules! for_alive {
            ($label:expr, $body:expr) => {{
                self.vlog(format_args!("== phase: {} ==", $label));
                for (idx, path) in files.iter().enumerate() {
                    if !alive[idx] {
                        continue;
                    }
                    let f: &mut dyn FnMut(&mut Self, &Path) -> io::Result<()> = $body;
                    if let Err(e) = f(self, path) {
                        eprintln!("override: {}: {e}", path.display());
                        alive[idx] = false;
                        summary.failed += 1;
                    }
                }
            }};
        }

        for_alive!("encrypt", &mut |s, p| s.phase_encrypt(p));
        for_alive!("random A", &mut |s, p| s.phase_random(p, "A"));
        for_alive!("null", &mut |s, p| s.phase_null(p));
        for_alive!("random B", &mut |s, p| s.phase_random(p, "B"));
        for_alive!("rename+delete", &mut |s, p| s.phase_rename_delete(p));

        summary.destroyed += alive.iter().filter(|&&a| a).count();
    }

    fn run_no_stop(&mut self, files: &[PathBuf], summary: &mut Summary) {
        self.vlog(format_args!(
            "no-stop: looping encrypt->random->null->random until interrupted (Ctrl-C once to finish, twice to abort)"
        ));
        let mut alive: Vec<bool> = vec![true; files.len()];
        let mut cycle: u64 = 0;

        while !signals::interrupted() {
            cycle += 1;
            self.vlog(format_args!("-- cycle {cycle} --"));
            for (idx, path) in files.iter().enumerate() {
                if !alive[idx] {
                    continue;
                }
                if let Err(e) = self.wipe_phases(path) {
                    eprintln!("override: {}: {e}", path.display());
                    alive[idx] = false;
                    summary.failed += 1;
                }
                if signals::interrupted() {
                    break;
                }
            }
        }

        self.vlog(format_args!("interrupt received; renaming and deleting targets"));
        for (idx, path) in files.iter().enumerate() {
            if !alive[idx] {
                continue;
            }
            match self.phase_rename_delete(path) {
                Ok(()) => summary.destroyed += 1,
                Err(e) => {
                    eprintln!("override: {}: {e}", path.display());
                    summary.failed += 1;
                }
            }
        }
    }
}
