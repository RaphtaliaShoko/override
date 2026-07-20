//! Overwrite phases (random / null) and the rename+delete phase.

use crate::signals;
use crate::source::ByteSource;
use crate::CHUNK;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// What to write during an overwrite pass.
pub enum Fill<'a> {
    /// Random bytes from the given source (CSPRNG or source file).
    Random(&'a mut ByteSource),
    /// Zero bytes.
    Null,
}

/// Overwrite the entire file (0..len) once, flush and fsync.
///
/// Real `write` syscalls are issued per chunk, which the compiler cannot
/// optimize away, and `sync_all` forces the data past the page cache.
///
/// `on_chunk` is called with the byte count of each chunk as it is written, so
/// callers can drive a progress bar without this module depending on one.
pub fn overwrite_pass(
    file: &mut File,
    len: u64,
    fill: &mut Fill,
    on_chunk: &mut dyn FnMut(u64),
) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    file.seek(SeekFrom::Start(0))?;

    let mut written: u64 = 0;
    while written < len {
        let this = std::cmp::min(CHUNK as u64, len - written) as usize;
        match fill {
            Fill::Random(src) => src.fill(&mut buf[..this]),
            Fill::Null => {
                for b in &mut buf[..this] {
                    *b = 0;
                }
            }
        }
        file.write_all(&buf[..this])?;
        written += this as u64;
        on_chunk(this as u64);

        // Graceful interrupt: stop after completing the current chunk write.
        if signals::interrupted() {
            break;
        }
    }
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

/// Fsync the directory that contains `path`, so a rename/unlink of an entry in
/// it is durably persisted (on crash-recovery, the directory entry is gone).
///
/// This is best-effort at the call site: the removal itself has already
/// happened by the time we get here; this only hardens the metadata's
/// durability. Returns an error if the parent cannot be opened or synced.
pub fn fsync_parent_dir(path: &Path) -> io::Result<()> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = parent.unwrap_or_else(|| Path::new("."));
    // Opening a directory read-only and calling fsync on it flushes its entries
    // on Linux/Unix.
    let f = File::open(dir)?;
    f.sync_all()
}

/// Generate a random file name of `len` hex-ish characters.
fn random_name(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut raw = vec![0u8; len];
    OsRng.fill_bytes(&mut raw);
    raw.iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

/// Rename `path` to a fresh random name in the same directory, `passes` times.
///
/// Each pass uses a new random name. Following `shred -u`, the names shrink on
/// successive passes to progressively erase length information from directory
/// entries. Returns the final path the file lives at.
pub fn rename_passes(path: &Path, passes: u32, verbose: bool) -> io::Result<PathBuf> {
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut current = path.to_path_buf();

    // Start from the original name length (min 1) and shrink toward 1.
    let start_len = path
        .file_name()
        .map(|n| n.to_string_lossy().len())
        .unwrap_or(8)
        .max(1);

    for pass in 0..passes {
        // Shrink the name length by one per pass, floored at 1.
        let name_len = start_len.saturating_sub(pass as usize).max(1);

        // Find an unused random name in the directory.
        let mut attempts = 0;
        let new_path = loop {
            let candidate = parent.join(random_name(name_len));
            if !candidate.exists() {
                break candidate;
            }
            attempts += 1;
            if attempts > 1000 {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "could not find a free random name",
                ));
            }
        };

        fs::rename(&current, &new_path)?;
        if verbose {
            println!(
                "    rename pass {}/{}: {} -> {}",
                pass + 1,
                passes,
                current.display(),
                new_path.display()
            );
        }
        current = new_path;

        if signals::interrupted() {
            // Renames are atomic; safe to stop between them.
            break;
        }
    }
    Ok(current)
}

/// Unlink the file from the filesystem.
pub fn delete(path: &Path) -> io::Result<()> {
    fs::remove_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Read, Write};

    fn read_all(path: &Path) -> Vec<u8> {
        let mut v = Vec::new();
        File::open(path).unwrap().read_to_end(&mut v).unwrap();
        v
    }

    #[test]
    fn null_pass_zeroes_entire_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&vec![0xFFu8; 4096]).unwrap();
        tmp.flush().unwrap();

        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(tmp.path())
            .unwrap();
        overwrite_pass(&mut f, 4096, &mut Fill::Null, &mut |_| {}).unwrap();

        assert_eq!(read_all(tmp.path()), vec![0u8; 4096]);
    }

    #[test]
    fn random_pass_changes_content_but_not_length() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let orig = vec![0xABu8; 4096];
        tmp.write_all(&orig).unwrap();
        tmp.flush().unwrap();

        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(tmp.path())
            .unwrap();
        let mut src = ByteSource::csprng();
        let mut counted: u64 = 0;
        overwrite_pass(&mut f, 4096, &mut Fill::Random(&mut src), &mut |n| {
            counted += n
        })
        .unwrap();

        let after = read_all(tmp.path());
        assert_eq!(after.len(), 4096);
        assert_ne!(after, orig);
        assert_eq!(counted, 4096, "callback should tally every byte");
    }

    #[test]
    fn fsync_parent_dir_succeeds_for_normal_dir() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f.txt");
        std::fs::write(&p, b"x").unwrap();
        // Syncing the parent of an existing file must succeed.
        fsync_parent_dir(&p).unwrap();
    }

    #[test]
    fn rename_then_delete_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("victim.txt");
        std::fs::write(&p, b"data").unwrap();

        let final_path = rename_passes(&p, 3, false).unwrap();
        assert!(!p.exists(), "original name should be gone");
        assert!(final_path.exists(), "renamed file exists until deleted");

        delete(&final_path).unwrap();
        assert!(!final_path.exists());
    }
}
