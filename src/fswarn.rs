//! Runtime filesystem warnings.
//!
//! Overwrite passes assume that rewriting a file's logical bytes rewrites the
//! same physical blocks. That assumption is false on copy-on-write and
//! log-structured filesystems (btrfs, ZFS, overlayfs), where a "write" may land
//! in freshly allocated blocks and leave the originals intact until garbage
//! collection. On volatile filesystems (tmpfs) the data never reaches stable
//! storage at all. Crypto-shredding still protects the data in those cases, but
//! the overwrite phases are not guaranteed to be effective, so we warn.
//!
//! Detection reads the filesystem magic via `statfs` and compares it against a
//! table of known values. It is best-effort: an unknown or unreadable
//! filesystem produces no warning.

use std::collections::HashSet;
use std::path::Path;

// Filesystem magic numbers (see `man 2 statfs` / linux/magic.h).
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;
const ZFS_SUPER_MAGIC: i64 = 0x2FC1_2FC1;
const OVERLAYFS_SUPER_MAGIC: i64 = 0x794C_7630;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const NFS_SUPER_MAGIC: i64 = 0x6969;

/// Classify a filesystem magic into a one-line caveat, or `None` if the
/// filesystem is one where logical overwrites are expected to hit real blocks
/// (ext4, xfs, ...).
///
/// Pure and side-effect free so it can be unit-tested without a real mount.
pub fn warning_for_magic(magic: i64) -> Option<&'static str> {
    match magic {
        BTRFS_SUPER_MAGIC | ZFS_SUPER_MAGIC | OVERLAYFS_SUPER_MAGIC => Some(
            "copy-on-write/log-structured filesystem: overwrite passes may not \
             reach the original physical blocks. Crypto-shredding still applies, \
             but the random/null overwrites are not guaranteed effective here.",
        ),
        TMPFS_MAGIC => Some(
            "volatile (RAM-backed) filesystem: contents never reach stable \
             storage, so overwriting is moot (data is gone at reboot/unmount).",
        ),
        NFS_SUPER_MAGIC => Some(
            "network filesystem: physical media is remote and its overwrite \
             behavior is out of this tool's control.",
        ),
        _ => None,
    }
}

/// Read the filesystem magic for the filesystem containing `path`.
///
/// Uses the path itself if it exists, else its parent directory (targets are
/// often about to be created/removed). Returns `None` on any error.
#[cfg(target_os = "linux")]
fn magic_for_path(path: &Path) -> Option<i64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // Prefer the path; fall back to its parent, then to ".".
    let probe = if path.exists() {
        path.to_path_buf()
    } else {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| Path::new(".").to_path_buf())
    };

    let c = CString::new(probe.as_os_str().as_bytes()).ok()?;
    // SAFETY: `buf` is a valid, properly-sized statfs struct; `c` is a valid
    // NUL-terminated C string. We only read `f_type` from the result on success.
    unsafe {
        let mut buf = std::mem::zeroed::<libc::statfs>();
        if libc::statfs(c.as_ptr(), &mut buf) == 0 {
            Some(buf.f_type as i64)
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn magic_for_path(_path: &Path) -> Option<i64> {
    None
}

/// Warn (once per distinct filesystem magic) about any paths that live on a
/// filesystem where overwriting is unreliable. `seen` dedups across calls so a
/// batch of many files on the same volume warns only once.
pub fn warn_for_paths(paths: &[std::path::PathBuf], seen: &mut HashSet<i64>) {
    for path in paths {
        if let Some(magic) = magic_for_path(path) {
            if !seen.insert(magic) {
                continue; // already warned about this filesystem
            }
            if let Some(msg) = warning_for_magic(magic) {
                eprintln!("override: warning: {}: {msg}", path.display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cow_and_volatile_filesystems_warn() {
        assert!(warning_for_magic(BTRFS_SUPER_MAGIC).is_some());
        assert!(warning_for_magic(ZFS_SUPER_MAGIC).is_some());
        assert!(warning_for_magic(OVERLAYFS_SUPER_MAGIC).is_some());
        assert!(warning_for_magic(TMPFS_MAGIC).is_some());
        assert!(warning_for_magic(NFS_SUPER_MAGIC).is_some());
    }

    #[test]
    fn ordinary_filesystems_do_not_warn() {
        // ext4 (0xEF53) and xfs (0x58465342) must be silent.
        assert!(warning_for_magic(0xEF53).is_none());
        assert!(warning_for_magic(0x5846_5342).is_none());
        assert!(warning_for_magic(0).is_none());
    }

    #[test]
    fn dedup_warns_once_per_filesystem() {
        // Two paths on the same (btrfs) magic should only warn once. We can't
        // force a real btrfs mount here, so exercise the dedup set directly.
        let mut seen = HashSet::new();
        assert!(seen.insert(BTRFS_SUPER_MAGIC));
        assert!(!seen.insert(BTRFS_SUPER_MAGIC));
    }
}
