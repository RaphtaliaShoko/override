//! Runtime filesystem warnings.
//!
//! Every destructive pass -- the random/null overwrites *and* the in-place
//! crypto-shred -- assumes that rewriting a file's logical bytes rewrites the
//! same physical blocks. That assumption is false on copy-on-write and
//! log-structured filesystems (btrfs, ZFS, overlayfs), where a "write" may land
//! in freshly allocated blocks and leave the originals intact until garbage
//! collection. Because the target's plaintext already exists on disk, the
//! crypto-shred pass gains no advantage there: re-encrypting in place can be
//! redirected to new blocks, leaving the original plaintext recoverable even
//! after the key is discarded. On volatile filesystems (tmpfs) the data never
//! reaches stable storage at all. So on these filesystems none of the passes
//! is guaranteed effective, and we warn.
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
const COW_MSG: &str = "copy-on-write/log-structured filesystem: a logical write can be \
     redirected to newly allocated blocks, leaving the original blocks intact. This \
     defeats the overwrite passes AND the in-place crypto-shred here -- the pre-existing \
     plaintext may survive on the original blocks even after the key is discarded, so \
     destruction cannot be assured. Prefer full-disk encryption, ATA/NVMe secure-erase, \
     or physical destruction.";
const VOLATILE_MSG: &str = "volatile (RAM-backed) filesystem: contents never reach stable \
     storage, so overwriting is moot (data is gone at reboot/unmount).";
const NETWORK_MSG: &str = "network filesystem: the physical media is remote and its write \
     behavior is out of this tool's control, so neither the overwrites nor the in-place \
     crypto-shred can be guaranteed to destroy the original blocks.";

// Filesystem magic numbers (see `man 2 statfs` / linux/magic.h).
const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E;
const ZFS_SUPER_MAGIC: i64 = 0x2FC1_2FC1;
const OVERLAYFS_SUPER_MAGIC: i64 = 0x794C_7630;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const NFS_SUPER_MAGIC: i64 = 0x6969;

/// A filesystem caveat: why in-place destruction may be unreliable here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caveat {
    /// Copy-on-write / log-structured / SSD-remapped: a logical write may land
    /// on freshly allocated blocks and leave the originals (with the plaintext)
    /// intact. This limits the crypto-shred exactly as it limits the overwrite
    /// passes, so destruction cannot be assured.
    CowRemap,
    /// Volatile (tmpfs): data never reaches stable storage and is gone at
    /// reboot/unmount, so a completed run does destroy the on-media copy.
    Volatile,
    /// Network: the physical media is remote and its write behavior is out of
    /// this tool's control, so destruction cannot be assured.
    Network,
}

impl Caveat {
    /// The one-line warning printed to stderr for this caveat.
    pub fn message(self) -> &'static str {
        match self {
            Caveat::CowRemap => COW_MSG,
            Caveat::Volatile => VOLATILE_MSG,
            Caveat::Network => NETWORK_MSG,
        }
    }

    /// Whether a *completed* run on such a filesystem can be trusted to have
    /// actually destroyed the data. False for the cases where the original
    /// physical blocks may survive (CoW/SSD remapping, remote media); true for
    /// tmpfs, whose contents are volatile anyway.
    pub fn assures_destruction(self) -> bool {
        matches!(self, Caveat::Volatile)
    }
}

/// Classify a filesystem magic into a [`Caveat`], or `None` if the filesystem is
/// one where logical overwrites are expected to hit real blocks (ext4, xfs,
/// ...). Linux only — the BSDs use [`warning_for_fstype`].
///
/// Pure and side-effect free so it can be unit-tested without a real mount.
pub fn warning_for_magic(magic: i64) -> Option<Caveat> {
    match magic {
        BTRFS_SUPER_MAGIC | ZFS_SUPER_MAGIC | OVERLAYFS_SUPER_MAGIC => Some(Caveat::CowRemap),
        TMPFS_MAGIC => Some(Caveat::Volatile),
        NFS_SUPER_MAGIC => Some(Caveat::Network),
        _ => None,
    }
}

/// Classify a BSD filesystem *type name* (`f_fstypename`) into the same caveats
/// as [`warning_for_magic`], or `None` for filesystems where overwriting is
/// expected to hit real blocks (ufs, ext2fs, ...). Matched case-insensitively.
///
/// Pure and side-effect free so it can be unit-tested without a real mount.
pub fn warning_for_fstype(name: &str) -> Option<Caveat> {
    // BSD type names: "zfs" (CoW), "tmpfs" (volatile), "nfs"/"oldnfs" (network).
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "zfs" => Some(Caveat::CowRemap),
        "tmpfs" => Some(Caveat::Volatile),
        "nfs" | "oldnfs" | "nfsv4" => Some(Caveat::Network),
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
fn fs_key_and_warning(path: &Path) -> Option<(i64, Option<Caveat>)> {
    let magic = magic_for_path(path)?;
    Some((magic, warning_for_magic(magic)))
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))]
fn fs_key_and_warning(path: &Path) -> Option<(i64, Option<Caveat>)> {
    let name = fstype_for_path(path)?;
    Some((key_for_name(&name), warning_for_fstype(&name)))
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd"
)))]
fn fs_key_and_warning(_path: &Path) -> Option<(i64, Option<Caveat>)> {
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
///
/// Returns the number of distinct filesystems seen where a completed run cannot
/// be trusted to have destroyed the data (CoW/SSD-remapped, network), so the
/// caller can qualify its "destroyed" summary. tmpfs is not counted (its
/// contents are volatile anyway).
pub fn warn_for_paths(paths: &[std::path::PathBuf], seen: &mut HashSet<i64>) -> usize {
    let mut unassured = 0;
    for path in paths {
        if let Some((key, caveat)) = fs_key_and_warning(path) {
            if !seen.insert(key) {
                continue; // already warned about (or cleared) this filesystem
            }
            if let Some(caveat) = caveat {
                eprintln!(
                    "override: warning: {}: {}",
                    path.display(),
                    caveat.message()
                );
                if !caveat.assures_destruction() {
                    unassured += 1;
                }
            }
        }
    }
    unassured
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cow_and_volatile_filesystems_warn() {
        assert_eq!(warning_for_magic(BTRFS_SUPER_MAGIC), Some(Caveat::CowRemap));
        assert_eq!(warning_for_magic(ZFS_SUPER_MAGIC), Some(Caveat::CowRemap));
        assert_eq!(
            warning_for_magic(OVERLAYFS_SUPER_MAGIC),
            Some(Caveat::CowRemap)
        );
        assert_eq!(warning_for_magic(TMPFS_MAGIC), Some(Caveat::Volatile));
        assert_eq!(warning_for_magic(NFS_SUPER_MAGIC), Some(Caveat::Network));
    }

    #[test]
    fn ordinary_filesystems_do_not_warn() {
        // ext4 (0xEF53) and xfs (0x58465342) must be silent.
        assert!(warning_for_magic(0xEF53).is_none());
        assert!(warning_for_magic(0x5846_5342).is_none());
        assert!(warning_for_magic(0).is_none());
    }

    #[test]
    fn cow_and_network_do_not_assure_destruction_but_tmpfs_does() {
        // The whole point of C-1: on CoW/SSD-remapped and network storage a
        // completed run cannot be trusted to have destroyed the data, so those
        // caveats must report `assures_destruction() == false`. tmpfs is gone at
        // reboot anyway, so it does assure destruction of the on-media copy.
        assert!(!Caveat::CowRemap.assures_destruction());
        assert!(!Caveat::Network.assures_destruction());
        assert!(Caveat::Volatile.assures_destruction());
    }

    #[test]
    fn bsd_type_names_classify_like_magic() {
        // The BSD path keys off f_fstypename strings instead of magic numbers.
        assert_eq!(warning_for_fstype("zfs"), Some(Caveat::CowRemap));
        assert_eq!(warning_for_fstype("tmpfs"), Some(Caveat::Volatile));
        assert_eq!(warning_for_fstype("nfs"), Some(Caveat::Network));
        assert_eq!(warning_for_fstype("NFS"), Some(Caveat::Network)); // case-insensitive
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
