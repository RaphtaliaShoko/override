//! Overwrite phases (random / null) and the rename+delete phase.

use crate::signals;
use crate::source::ByteSource;
use crate::CHUNK;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::{CString, OsStr};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// What to write during an overwrite pass.
pub enum Fill<'a> {
    /// Random bytes from the given source (CSPRNG or source file).
    Random(&'a mut ByteSource),
    /// Zero bytes.
    Null,
}

/// Identity of a target captured at scan time (device + inode on Unix).
///
/// The pipeline re-opens each target by path once per pass/phase, which on its
/// own is vulnerable to a symlink/rename race: a local attacker with write
/// access to the containing directory could swap the file for a symlink between
/// checks and redirect `override`'s destructive writes onto another file. To
/// close that window, every open re-checks the opened inode against the `FileId`
/// recorded during collection and aborts the target on any mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl FileId {
    /// Record identity from metadata obtained at scan time (an `lstat`, so the
    /// recorded inode is the target itself, never a symlink's referent).
    pub fn of(meta: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            // `MetadataExt::dev`/`ino` both return `u64` on every Unix target.
            FileId {
                dev: meta.dev(),
                ino: meta.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = meta;
            FileId {}
        }
    }

    #[cfg(unix)]
    fn matches(&self, meta: &std::fs::Metadata) -> bool {
        meta.dev() == self.dev && meta.ino() == self.ino
    }
}

/// Open a target read+write for an overwrite/encrypt pass.
///
/// On Unix this refuses to follow a symlink in the final path component
/// (`O_NOFOLLOW`, which fails with `ELOOP` if the name is now a symlink) and
/// verifies the opened inode is still the regular file recorded at scan time.
/// Together these close the symlink-follow + TOCTOU window in which a swapped
/// path could redirect destructive writes onto an arbitrary file.
pub fn open_target(path: &Path, id: &FileId) -> io::Result<(File, u64)> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);

    let file = opts.open(path)?;
    let meta = file.metadata()?;

    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target is no longer a regular file; refusing to overwrite it",
        ));
    }
    #[cfg(unix)]
    if !id.matches(&meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target changed since it was scanned (possible symlink/rename race); aborting",
        ));
    }
    #[cfg(not(unix))]
    let _ = id;

    Ok((file, meta.len()))
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

/// Generate a random file name of `len` characters.
fn random_name(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut raw = vec![0u8; len];
    OsRng.fill_bytes(&mut raw);
    raw.iter()
        .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
        .collect()
}

/// The name length to use on rename pass `pass`, shrinking by one per pass
/// (floored at 1) starting from the original name length — this erases length
/// information from directory entries, following `shred -u`.
fn rename_len(start_len: usize, pass: u32) -> usize {
    start_len.saturating_sub(pass as usize).max(1)
}

// ---- directory-relative finalize (rename / unlink), Unix ------------------
//
// The finalize phase originally resolved the target by full path
// (`fs::rename` / `fs::remove_file`), which — like the per-pass opens — is
// racy: an intermediate directory component swapped for a symlink between the
// overwrite phase and the rename/unlink could move the operation into a
// different directory. Holding one fd on the parent directory and performing
// every step (`renameat`/`unlinkat`, existence checks, the final `fsync`)
// relative to it pins the operations to the real directory inode we scanned,
// independent of any later path-component substitution.

/// A parent directory held open by fd, so rename/unlink/fsync all resolve
/// relative to the same real directory inode rather than by path.
#[cfg(unix)]
struct ParentDir {
    dir: File,
    path: PathBuf,
}

#[cfg(unix)]
impl ParentDir {
    fn open(target: &Path) -> io::Result<Self> {
        let path = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        // Read-only is enough: renameat/unlinkat need write+exec on the
        // directory itself (checked at the call), not on this handle.
        let dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(&path)?;
        Ok(ParentDir { dir, path })
    }

    fn fd(&self) -> std::os::unix::io::RawFd {
        self.dir.as_raw_fd()
    }

    fn cname(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
    }

    /// Whether an entry `name` already exists in this directory (not following a
    /// final-component symlink, so a dangling symlink still counts as taken).
    fn entry_exists(&self, name: &OsStr) -> bool {
        let c = match Self::cname(name) {
            Ok(c) => c,
            Err(_) => return true,
        };
        unsafe {
            libc::faccessat(self.fd(), c.as_ptr(), libc::F_OK, libc::AT_SYMLINK_NOFOLLOW) == 0
        }
    }

    fn rename(&self, old: &OsStr, new: &OsStr) -> io::Result<()> {
        let o = Self::cname(old)?;
        let n = Self::cname(new)?;
        // SAFETY: both fds refer to this open directory; pointers are valid
        // NUL-terminated names for the duration of the call.
        if unsafe { libc::renameat(self.fd(), o.as_ptr(), self.fd(), n.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Verify `name` still resolves (without following a symlink) to the exact
    /// regular-file inode recorded at scan time, then unlink it — so a
    /// last-moment swap cannot redirect the unlink onto another object.
    fn verify_and_unlink(&self, name: &OsStr, id: &FileId) -> io::Result<()> {
        let c = Self::cname(name)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(self.fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let is_regular = (st.st_mode & libc::S_IFMT) == libc::S_IFREG;
        if !is_regular || st.st_dev as u64 != id.dev || st.st_ino as u64 != id.ino {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target changed since it was scanned (possible symlink/rename race); \
                 refusing to unlink",
            ));
        }
        if unsafe { libc::unlinkat(self.fd(), c.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Fsync the directory so the rename/unlink is durably persisted.
    fn sync(&self) -> io::Result<()> {
        self.dir.sync_all()
    }
}

/// Rename `path` to a fresh random name in the same directory, `passes` times.
///
/// Each pass uses a new random name; names shrink on successive passes to erase
/// length information from directory entries. All renames run relative to a held
/// parent-directory fd, so an intervening path-component swap cannot redirect
/// them. Returns the final path the file lives at.
#[cfg(unix)]
pub fn rename_passes(path: &Path, passes: u32, verbose: bool) -> io::Result<PathBuf> {
    let dir = ParentDir::open(path)?;
    let mut current: std::ffi::OsString = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target has no file name"))?
        .to_os_string();

    let start_len = current.to_string_lossy().len().max(1);

    for pass in 0..passes {
        let name_len = rename_len(start_len, pass);

        // Find an unused random name in the directory (relative to the fd).
        let mut attempts = 0;
        let new_name = loop {
            let candidate = std::ffi::OsString::from(random_name(name_len));
            if !dir.entry_exists(&candidate) {
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

        dir.rename(&current, &new_name)?;
        if verbose {
            println!(
                "    rename pass {}/{}: {} -> {}",
                pass + 1,
                passes,
                dir.path.join(&current).display(),
                dir.path.join(&new_name).display()
            );
        }
        current = new_name;

        if signals::interrupted() {
            // Renames are atomic; safe to stop between them.
            break;
        }
    }
    Ok(dir.path.join(&current))
}

/// Unlink the file (verified to still be the scanned inode) relative to its
/// parent-directory fd, then fsync that directory to persist the removal.
#[cfg(unix)]
pub fn delete(path: &Path, id: &FileId) -> io::Result<()> {
    let dir = ParentDir::open(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "target has no file name"))?;
    dir.verify_and_unlink(name, id)?;
    // Best-effort durability: the entry is already gone; only metadata
    // persistence remains, so a failed fsync does not fail the target.
    let _ = dir.sync();
    Ok(())
}

// ---- non-Unix fallback (Windows dropped, but keep the crate portable) -----

/// Path-based rename fallback for non-Unix targets.
#[cfg(not(unix))]
pub fn rename_passes(path: &Path, passes: u32, verbose: bool) -> io::Result<PathBuf> {
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut current = path.to_path_buf();
    let start_len = path
        .file_name()
        .map(|n| n.to_string_lossy().len())
        .unwrap_or(8)
        .max(1);

    for pass in 0..passes {
        let name_len = rename_len(start_len, pass);
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
        std::fs::rename(&current, &new_path)?;
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
            break;
        }
    }
    Ok(current)
}

/// Path-based unlink fallback for non-Unix targets.
#[cfg(not(unix))]
pub fn delete(path: &Path, _id: &FileId) -> io::Result<()> {
    std::fs::remove_file(path)?;
    let _ = fsync_parent_dir(path);
    Ok(())
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

        let id = FileId::of(&std::fs::symlink_metadata(&p).unwrap());
        let final_path = rename_passes(&p, 3, false).unwrap();
        assert!(!p.exists(), "original name should be gone");
        assert!(final_path.exists(), "renamed file exists until deleted");

        // The inode survives the rename, so the scan-time id still matches.
        delete(&final_path, &id).unwrap();
        assert!(!final_path.exists());
    }

    // ---- security regression tests (audit H-1 / M-1) --------------------

    #[test]
    fn open_target_accepts_the_unchanged_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("victim.bin");
        std::fs::write(&p, vec![0u8; 1234]).unwrap();
        let id = FileId::of(&std::fs::symlink_metadata(&p).unwrap());

        let (_file, len) = open_target(&p, &id).unwrap();
        assert_eq!(len, 1234);
    }

    /// A path that was a regular file at scan time but is now a symlink must not
    /// be followed: `O_NOFOLLOW` makes the open itself fail (audit H-1).
    #[cfg(unix)]
    #[test]
    fn open_target_refuses_a_swapped_in_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        let bystander = dir.path().join("bystander");
        std::fs::write(&victim, b"scanned").unwrap();
        std::fs::write(&bystander, b"must survive").unwrap();

        let id = FileId::of(&std::fs::symlink_metadata(&victim).unwrap());

        // Attacker swaps the target for a symlink to another file.
        std::fs::remove_file(&victim).unwrap();
        std::os::unix::fs::symlink(&bystander, &victim).unwrap();

        assert!(
            open_target(&victim, &id).is_err(),
            "open must refuse to follow the symlink"
        );
        assert_eq!(
            std::fs::read(&bystander).unwrap(),
            b"must survive",
            "the symlink's target must be untouched"
        );
    }

    /// A path replaced by a *different* regular file after scanning must be
    /// rejected on the inode-identity check (audit H-1).
    #[cfg(unix)]
    #[test]
    fn open_target_detects_an_inode_swap() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"scanned").unwrap();
        let id = FileId::of(&std::fs::symlink_metadata(&victim).unwrap());

        // Replace with a brand-new regular file at the same path (new inode).
        std::fs::remove_file(&victim).unwrap();
        std::fs::write(&victim, b"impostor").unwrap();

        assert!(
            open_target(&victim, &id).is_err(),
            "open must reject a different inode at the same path"
        );
    }

    /// `delete` must refuse to unlink when the entry no longer resolves to the
    /// scanned inode (audit M-1).
    #[cfg(unix)]
    #[test]
    fn delete_refuses_when_the_inode_changed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"scanned").unwrap();
        let id = FileId::of(&std::fs::symlink_metadata(&victim).unwrap());

        std::fs::remove_file(&victim).unwrap();
        std::fs::write(&victim, b"impostor").unwrap();

        assert!(
            delete(&victim, &id).is_err(),
            "must not unlink a swapped file"
        );
        assert!(victim.exists(), "the impostor must be left in place");
    }
}
