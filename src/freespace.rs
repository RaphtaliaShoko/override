//! Free-space wiping.
//!
//! Fills the unused space of a filesystem with random (then optionally zero)
//! data so that remnants of files deleted *before* `override` ran can no longer
//! be recovered from the free blocks. This is the companion to per-file
//! shredding: shredding scrubs a file you still have; this scrubs what is left
//! of files you already deleted.
//!
//! Mechanism: create a single fill file in the target directory and write to it
//! until the filesystem reports `ENOSPC`, forcing the previously-free blocks to
//! be overwritten. A cleanup guard removes the fill file on every exit path
//! (success, error, or interrupt) so the volume is never left full.
//!
//! Limitations (documented in `--help`/README): does not reach slack space
//! inside still-allocated blocks, does not scrub filesystem metadata/journals,
//! and is ineffective where writes are remapped (copy-on-write filesystems,
//! flash translation layers on SSDs).

use crate::overwrite::Fill;
use crate::progress::Progress;
use crate::signals;
use crate::source::ByteSource;
use crate::CHUNK;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// RAII guard that removes the fill file whenever it goes out of scope.
struct FillFileGuard {
    path: PathBuf,
}

impl Drop for FillFileGuard {
    fn drop(&mut self) {
        // Best-effort: nothing useful to do if removal fails during unwinding.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Generate a random, hidden fill-file name so it is unlikely to collide.
fn fill_file_name() -> String {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut raw = [0u8; 12];
    OsRng.fill_bytes(&mut raw);
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    format!(".override-fill-{hex}")
}

/// Wipe the free space of the filesystem that hosts `dir`.
///
/// - `passes`: number of random-fill passes (from `-i`).
/// - `null_passes`: number of zero-fill passes (from `-n`).
/// - `source`: byte source for the random passes (CSPRNG or `--source`).
/// - `limit`: optional cap on bytes written per pass; `None` means "until the
///   filesystem is full". Used by tests to avoid actually filling a real disk.
///
/// Returns `Ok(())` once the free space has been overwritten and the fill file
/// removed. A first interrupt stops early but still cleans up.
pub fn wipe_free(
    dir: &Path,
    passes: u32,
    null_passes: u32,
    source: &mut ByteSource,
    verbose: bool,
    progress: &Progress,
    limit: Option<u64>,
) -> io::Result<()> {
    let meta = std::fs::metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: not a directory", dir.display()),
        ));
    }

    let path = dir.join(fill_file_name());
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)?;
    // From here on, the file is removed on any exit path.
    let _guard = FillFileGuard { path: path.clone() };

    if verbose {
        println!(
            "free-space wipe: filling {} ({} random + {} null pass(es))",
            dir.display(),
            passes,
            null_passes
        );
    }

    for pass in 1..=passes {
        if signals::interrupted() {
            break;
        }
        if verbose {
            println!("  [free random] pass {pass}/{passes}");
        }
        fill_until_full(&mut file, &mut Fill::Random(source), progress, limit)?;
    }

    for pass in 1..=null_passes {
        if signals::interrupted() {
            break;
        }
        if verbose {
            println!("  [free null] pass {pass}/{null_passes}");
        }
        fill_until_full(&mut file, &mut Fill::Null, progress, limit)?;
    }

    if verbose {
        println!("free-space wipe: removing fill file and syncing directory");
    }
    // Drop the file handle before the guard removes it.
    drop(file);
    drop(_guard);
    crate::overwrite::fsync_parent_dir(&path)?;
    Ok(())
}

/// Write `fill` bytes to `file` from offset 0 until the filesystem is full
/// (`ENOSPC`), the `limit` is reached, or an interrupt arrives.
fn fill_until_full(
    file: &mut File,
    fill: &mut Fill,
    progress: &Progress,
    limit: Option<u64>,
) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    file.seek(SeekFrom::Start(0))?;

    let mut written: u64 = 0;
    loop {
        if signals::interrupted() {
            break;
        }
        if let Some(cap) = limit {
            if written >= cap {
                break;
            }
        }

        let this = match limit {
            Some(cap) => std::cmp::min(CHUNK as u64, cap - written) as usize,
            None => CHUNK,
        };

        match fill {
            Fill::Random(src) => src.fill(&mut buf[..this]),
            Fill::Null => buf[..this].fill(0),
        }

        match file.write_all(&buf[..this]) {
            Ok(()) => {
                written += this as u64;
                progress.inc(this as u64);
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {
                // Filesystem is full: exactly the state we wanted to reach.
                break;
            }
            Err(e) => return Err(e),
        }
    }

    file.flush()?;
    // Force the fill data past the page cache so the free blocks are really
    // overwritten on the media. sync_all can itself surface a deferred ENOSPC.
    match file.sync_all() {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {}
        Err(e) => return Err(e),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_free_with_limit_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let mut src = ByteSource::csprng();
        let progress = Progress::hidden();

        // Cap each pass at 256 KiB so we never fill the real disk.
        wipe_free(
            dir.path(),
            2,
            1,
            &mut src,
            false,
            &progress,
            Some(256 * 1024),
        )
        .unwrap();

        // The fill file must be gone and the directory left empty.
        let remaining: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(
            remaining.is_empty(),
            "fill file was not cleaned up: {} entries left",
            remaining.len()
        );
    }

    #[test]
    fn wipe_free_rejects_non_directory() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut src = ByteSource::csprng();
        let progress = Progress::hidden();
        let err = wipe_free(tmp.path(), 1, 0, &mut src, false, &progress, Some(1024)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
