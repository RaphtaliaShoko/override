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
//! Detection is platform-specific. On **Linux** it reads the filesystem magic
//! via `statfs` and matches a table of known magic numbers. On the **BSDs** the
//! magic-number space does not exist; instead `statfs`/`statvfs` report a
//! filesystem *type name* string (`"zfs"`, `"tmpfs"`, ...) which we classify.
//! Either way it is best-effort: an unknown or unreadable filesystem produces
//! no warning, and platforms with neither probe stay silent.

use std::collections::HashSet;
use std::path::Path;

// The three caveat messages, shared by the magic-number (Linux) and type-name
// (BSD) classifiers so both platforms warn with identical wording.
const COW_MSG: &str = "copy-on-write/log-structured filesystem: overwrite passes may not \
     reach the original physical blocks. Crypto-shredding still applies, \
     but the random/null overwrites are not guaranteed effective here.";
const VOLATILE_MSG: &str = "volatile (RAM-backed) filesystem: contents never reach stable \
     storage, so overwriting is moot (data is gone at reboot/unmount).";
const NETWORK_MSG: &str = "network filesystem: physical media is remote and its overwrite \
     behavior is out of this tool's control.";

// Filesystem magic numbers (see `man 2 statfs` / linux/magic.h).
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;
const ZFS_SUPER_MAGIC: i64 = 0x2FC1_2FC1;
const OVERLAYFS_SUPER_MAGIC: i64 = 0x794C_7630;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const NFS_SUPER_MAGIC: i64 = 0x6969;

/// Classify a filesystem magic into a one-line caveat, or `None` if the
/// filesystem is one where logical overwrites are expected to hit real blocks
/// (ext4, xfs, ...). Linux only — the BSDs use [`warning_for_fstype`].
///
/// Pure and side-effect free so it can be unit-tested without a real mount.
pub fn warning_for_magic(magic: i64) -> Option<&'static str> {
    match magic {
        BTRFS_SUPER_MAGIC | ZFS_SUPER_MAGIC | OVERLAYFS_SUPER_MAGIC => Some(COW_MSG),
        TMPFS_MAGIC => Some(VOLATILE_MSG),
        NFS_SUPER_MAGIC => Some(NETWORK_MSG),
        _ => None,
    }
}

/// Classify a BSD filesystem *type name* (`f_fstypename`) into the same caveats
/// as [`warning_for_magic`], or `None` for filesystems where overwriting is
/// expected to hit real blocks (ufs, ext2fs, ...). Matched case-insensitively.
///
/// Pure and side-effect free so it can be unit-tested without a real mount.
pub fn warning_for_fstype(name: &str) -> Option<&'static str> {
    // BSD type names: "zfs" (CoW), "tmpfs" (volatile), "nfs"/"oldnfs" (network).
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "zfs" => Some(COW_MSG),
        "tmpfs" => Some(VOLATILE_MSG),
        "nfs" | "oldnfs" | "nfsv4" => Some(NETWORK_MSG),
        _ => None,
    }
}

/// The path whose filesystem we actually probe: the target if it exists, else
/// its parent directory (targets are often about to be created/removed), else
/// the current directory. Pure; platform-independent.
fn probe_path(path: &Path) -> std::path::PathBuf {
    if path.exists() {
        path.to_path_buf()
    } else {
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| Path::new(".").to_path_buf())
    }
}

/// Read the filesystem magic for the filesystem containing `path` (Linux).
#[cfg(target_os = "linux")]
fn magic_for_path(path: &Path) -> Option<i64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c = CString::new(probe_path(path).as_os_str().as_bytes()).ok()?;
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

/// Read the filesystem type name (`f_fstypename`) for the filesystem containing
/// `path` (FreeBSD/DragonFly/OpenBSD, which expose it on `struct statfs`).
#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))]
fn fstype_for_path(path: &Path) -> Option<String> {
    use std::ffi::{CStr, CString};
    use std::os::unix::ffi::OsStrExt;

    let c = CString::new(probe_path(path).as_os_str().as_bytes()).ok()?;
    // SAFETY: `buf` is a valid, properly-sized statfs struct; `c` is a valid
    // NUL-terminated C string. On success `f_fstypename` is a NUL-terminated
    // ASCII name we copy out before `buf` is dropped.
    unsafe {
        let mut buf = std::mem::zeroed::<libc::statfs>();
        if libc::statfs(c.as_ptr(), &mut buf) == 0 {
            let name = CStr::from_ptr(buf.f_fstypename.as_ptr());
            Some(name.to_string_lossy().into_owned())
        } else {
            None
        }
    }
}

/// Probe `path`'s filesystem, returning a stable per-filesystem dedup key plus
/// its caveat (if any). Platform-specific; `None` where no probe is available.
///
/// The dedup key differs by platform (Linux: the magic; BSD: a hash of the type
/// name) but is only ever compared for equality within one run, so a mix of
/// key spaces never occurs.
#[cfg(target_os = "linux")]
fn fs_key_and_warning(path: &Path) -> Option<(i64, Option<&'static str>)> {
    let magic = magic_for_path(path)?;
    Some((magic, warning_for_magic(magic)))
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))]
fn fs_key_and_warning(path: &Path) -> Option<(i64, Option<&'static str>)> {
    let name = fstype_for_path(path)?;
    Some((key_for_name(&name), warning_for_fstype(&name)))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd"
)))]
fn fs_key_and_warning(_path: &Path) -> Option<(i64, Option<&'static str>)> {
    None
}

/// Stable dedup key for a filesystem type name (BSD). Any collision only causes
/// one warning to be suppressed, so a fast non-cryptographic hash is fine.
#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))]
fn key_for_name(name: &str) -> i64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    name.to_ascii_lowercase().hash(&mut h);
    h.finish() as i64
}

/// Warn (once per distinct filesystem) about any paths that live on a
/// filesystem where overwriting is unreliable. `seen` dedups across calls so a
/// batch of many files on the same volume warns only once.
pub fn warn_for_paths(paths: &[std::path::PathBuf], seen: &mut HashSet<i64>) {
    for path in paths {
        if let Some((key, warning)) = fs_key_and_warning(path) {
            if !seen.insert(key) {
                continue; // already warned about (or cleared) this filesystem
            }
            if let Some(msg) = warning {
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
    fn bsd_type_names_classify_like_magic() {
        // The BSD path keys off f_fstypename strings instead of magic numbers.
        assert_eq!(warning_for_fstype("zfs"), Some(COW_MSG));
        assert_eq!(warning_for_fstype("tmpfs"), Some(VOLATILE_MSG));
        assert_eq!(warning_for_fstype("nfs"), Some(NETWORK_MSG));
        assert_eq!(warning_for_fstype("NFS"), Some(NETWORK_MSG)); // case-insensitive
        // ufs (BSD's native, non-CoW fs) and ext2fs must stay silent.
        assert!(warning_for_fstype("ufs").is_none());
        assert!(warning_for_fstype("ext2fs").is_none());
        assert!(warning_for_fstype("").is_none());
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
