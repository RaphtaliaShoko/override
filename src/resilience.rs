//! Self-resilience: make the running process independent of its on-disk
//! executable so it survives being deleted, overwritten, or shredded by itself.
//!
//! Strategy (Linux): at startup, copy the process's own executable image into
//! an anonymous, memory-backed file (`memfd_create`) and re-execute from that
//! memfd via `fexecve`. After the re-exec, the process image is backed by the
//! anonymous memfd; nothing that happens to the original on-disk file (unlink,
//! truncate, overwrite) can unmap pages or cause SIGBUS.
//!
//! Strategy (FreeBSD): the same idea using FreeBSD's analogue of a memfd — an
//! anonymous shared-memory object (`shm_open(SHM_ANON)`) — plus `fexecve`. The
//! own-executable path comes from the `kern.proc.pathname` sysctl rather than
//! `/proc/self/exe` (procfs is usually not mounted on FreeBSD).
//!
//! Other platforms (OpenBSD, DragonFly, NetBSD, macOS, ...) have no anonymous
//! executable-memory + `fexecve` combination we can rely on, so re-exec is a
//! no-op there and resilience rests solely on the static build keeping its
//! pages resident.
//!
//! Combined with a statically linked (musl) build there are no external shared
//! objects to lose either. See the README for platform scope and limitations.
//!
//! This is best-effort: if any step fails we log a note (only in verbose mode)
//! and continue running from the on-disk image, relying on the fact that a
//! static build already keeps its pages resident.

/// Env var used to break the re-exec loop: set on the child so it does not try
/// to re-exec again.
const GUARD: &str = "OVERRIDE_MEMFD_REEXEC";

/// Re-execute the current process from an in-memory copy of its executable.
///
/// On success this never returns (the process image is replaced). On failure,
/// or if already re-executed, it returns and the caller continues normally.
pub fn reexec_from_memfd(verbose: bool) {
    // Two independent loop guards, so a single failure cannot cause an infinite
    // re-exec (each iteration would allocate a fresh memfd):
    //   1. the GUARD env var we set on the child (fast, no syscall), and
    //   2. an env-independent check that our own image is already a memfd.
    // The env var alone is not enough: a sandbox/CI that sanitizes the
    // environment could strip it between the re-exec and the child's startup,
    // and the child would then re-exec forever. The proc check below cannot be
    // stripped, so it breaks the loop even if the env var is gone.
    if std::env::var_os(GUARD).is_some() || running_from_memfd() {
        if verbose {
            eprintln!("[resilience] running from in-memory image");
        }
        return; // Already running from the memfd copy.
    }

    match try_reexec() {
        Ok(()) => unreachable!("fexecve returned without replacing the image"),
        Err(e) => {
            if verbose {
                eprintln!(
                    "[resilience] memfd re-exec unavailable ({e}); continuing from on-disk image"
                );
            }
        }
    }
}

/// Are we already executing from an in-memory (memfd) image?
///
/// A process exec'd from a memfd via `fexecve` has its `/proc/self/exe` symlink
/// point at a target like `/memfd:override (deleted)`. We match the `/memfd:`
/// prefix specifically: a *normally* unlinked on-disk binary also reports the
/// trailing `(deleted)`, so matching on that alone would be wrong.
#[cfg(target_os = "linux")]
fn running_from_memfd() -> bool {
    match std::fs::read_link("/proc/self/exe") {
        Ok(target) => target.to_string_lossy().starts_with("/memfd:"),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn running_from_memfd() -> bool {
    false
}

/// Rebuild `argv` and `envp` for the re-exec, adding the loop-guard env var so
/// the child does not re-exec again. Shared by the Linux and FreeBSD paths.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn build_argv_envp() -> (Vec<std::ffi::CString>, Vec<std::ffi::CString>) {
    use std::ffi::CString;

    let argv: Vec<CString> = std::env::args_os()
        .map(|a| {
            CString::new(a.to_string_lossy().into_owned())
                .unwrap_or_else(|_| CString::new("").unwrap())
        })
        .collect();

    let mut envp: Vec<CString> = std::env::vars_os()
        .filter(|(k, _)| k != GUARD)
        .map(|(k, v)| {
            CString::new(format!("{}={}", k.to_string_lossy(), v.to_string_lossy()))
                .unwrap_or_else(|_| CString::new("PLACEHOLDER=1").unwrap())
        })
        .collect();
    envp.push(CString::new(format!("{GUARD}=1")).unwrap());

    (argv, envp)
}

#[cfg(target_os = "linux")]
fn try_reexec() -> std::io::Result<()> {
    use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    // Read our own executable image. /proc/self/exe still resolves even if the
    // path has since been unlinked, and reads the real backing file.
    let image = std::fs::read("/proc/self/exe")?;

    // Anonymous memory-backed fd. No CLOEXEC: the fd must survive fexecve.
    let name = CString::new("override").unwrap();
    let memfd = memfd_create(&name, MemFdCreateFlag::empty())
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;

    // Write the image into the memfd.
    {
        let mut f = unsafe {
            use std::os::fd::{FromRawFd, IntoRawFd};
            // Duplicate ownership handling: build a File that writes to the fd
            // without taking ownership of the OwnedFd we still need for exec.
            let raw = memfd.as_raw_fd();
            let dup =
                nix::unistd::dup(raw).map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            std::fs::File::from_raw_fd(dup.into_raw_fd())
        };
        f.write_all(&image)?;
        f.flush()?;
    }

    let (argv, envp) = build_argv_envp();

    // Replace the process image. On success this does not return.
    nix::unistd::fexecve(memfd.as_raw_fd(), &argv, &envp)
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    Ok(())
}

/// Resolve this process's own executable path via the `kern.proc.pathname`
/// sysctl. FreeBSD has no reliable `/proc/self/exe` (procfs is often unmounted).
#[cfg(target_os = "freebsd")]
fn own_exe_path() -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::ffi::OsStringExt;

    // MIB: kern.proc.pathname.-1  (-1 selects the calling process).
    let mut mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PATHNAME,
        -1,
    ];

    // First call with a null buffer to learn the required length.
    let mut len: libc::size_t = 0;
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Second call to fetch the path itself.
    let mut buf = vec![0u8; len];
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // `len` now counts the bytes written, including a trailing NUL.
    buf.truncate(len);
    if buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(std::path::PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

#[cfg(target_os = "freebsd")]
fn try_reexec() -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::FromRawFd;

    // Read our own executable image (path resolved via sysctl; see above). Once
    // we are already running from an anonymous shm object this path no longer
    // resolves, which also naturally stops any re-exec loop.
    let path = own_exe_path()?;
    let image = std::fs::read(&path)?;

    // Anonymous shared-memory object: unnamed, reclaimed when the last fd
    // closes, and executable via fexecve — FreeBSD's analogue of a Linux memfd.
    // No O_CLOEXEC: the fd must survive the exec.
    let fd = unsafe { libc::shm_open(libc::SHM_ANON, libc::O_RDWR, 0o600) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Own the fd through a File so it is closed if we return early (e.g. a
    // fexecve failure). On success fexecve replaces the image and this File is
    // never dropped.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(&image)?;
    file.flush()?;

    let (argv, envp) = build_argv_envp();

    // Replace the process image. On success this does not return.
    nix::unistd::fexecve(fd, &argv, &envp)
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn try_reexec() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "in-memory re-exec is only implemented on Linux and FreeBSD",
    ))
}
