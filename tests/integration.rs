//! Integration tests: drive the compiled `override` binary against disposable
//! files under a temp dir and verify end-to-end behavior.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Path to the compiled binary under test (provided by Cargo).
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_override")
}

fn write_file(path: &Path, contents: &[u8]) {
    let mut f = fs::File::create(path).unwrap();
    f.write_all(contents).unwrap();
    f.flush().unwrap();
}

/// Count regular files under a directory (recursively).
fn count_files(dir: &Path) -> usize {
    let mut n = 0;
    for entry in fs::read_dir(dir).unwrap() {
        let e = entry.unwrap();
        let ft = e.file_type().unwrap();
        if ft.is_dir() {
            n += count_files(&e.path());
        } else if ft.is_file() {
            n += 1;
        }
    }
    n
}

#[test]
fn end_to_end_pipeline_destroys_files() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.bin");
    write_file(&a, b"secret alpha content");
    write_file(&b, &vec![0xABu8; 50_000]);

    let status = Command::new(bin())
        .arg("-v")
        .arg(&a)
        .arg(&b)
        .status()
        .unwrap();

    assert!(status.success());
    assert!(!a.exists(), "a.txt should be gone");
    assert!(!b.exists(), "b.bin should be gone");
    assert_eq!(count_files(dir.path()), 0);
}

#[test]
fn recursive_and_batch_modes() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    write_file(&dir.path().join("top.log"), b"top");
    write_file(&sub.join("nested.log"), b"nested");
    write_file(&sub.join("nested2.log"), b"nested2");

    let status = Command::new(bin())
        .args(["-v", "-r", "-o", "batch"])
        .arg(dir.path())
        .status()
        .unwrap();

    assert!(status.success());
    assert_eq!(count_files(dir.path()), 0, "all files removed recursively");
}

#[test]
fn directory_without_recursive_errors_but_processes_siblings() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().join("adir");
    fs::create_dir(&d).unwrap();
    write_file(&d.join("inside"), b"x");
    let sibling = dir.path().join("sibling.txt");
    write_file(&sibling, b"kill me");

    let out = Command::new(bin())
        .arg(&d) // directory, no -r  -> error for this target
        .arg(&sibling) // regular file -> destroyed
        .output()
        .unwrap();

    // Non-zero exit because one target failed...
    assert!(!out.status.success());
    // ...but the sibling regular file was still destroyed.
    assert!(!sibling.exists(), "sibling should be destroyed");
    // ...and the directory + its file were left intact.
    assert!(d.join("inside").exists(), "directory content untouched");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("is a directory"), "stderr: {stderr}");
}

#[test]
fn source_file_overwrite_mode() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("source.dat");
    write_file(&src, b"0123456789");
    let target = dir.path().join("target.dat");
    write_file(&target, &vec![7u8; 4096]);

    let status = Command::new(bin())
        .args(["-e", "0", "-n", "0", "-i", "1", "-s"])
        .arg(&src)
        .arg(&target)
        .status()
        .unwrap();

    assert!(status.success());
    assert!(!target.exists());
    assert!(src.exists(), "source file itself must not be destroyed");
}

/// `--no-stop` can be started and cleanly interrupted, after which the target
/// is still renamed+deleted.
#[test]
fn no_stop_can_be_interrupted_and_still_deletes() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("loopme.bin");
    write_file(&target, &vec![0x5Au8; 100_000]);

    let mut child: Child = Command::new(bin())
        .args(["--no-stop", "-v"])
        .arg(&target)
        .spawn()
        .unwrap();

    // Let it loop a bit, then send SIGINT.
    std::thread::sleep(Duration::from_millis(800));
    send_sigint(child.id());

    // It should exit on its own within a few seconds.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "exit status: {status:?}");
            break;
        }
        assert!(Instant::now() < deadline, "no-stop did not exit after SIGINT");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!target.exists(), "target must be deleted after interrupt");
}

/// Self-resilience: copy the binary into a disposable dir and have it destroy a
/// set of files that INCLUDES its own executable copy. It must run to
/// completion and remove everything without crashing.
#[test]
fn self_resilience_shreds_own_binary() {
    let dir = tempfile::tempdir().unwrap();
    let exe_copy: PathBuf = dir.path().join("override_copy");
    fs::copy(bin(), &exe_copy).unwrap();
    // Make it executable (copy preserves perms, but be explicit).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&exe_copy, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let v1 = dir.path().join("victim1");
    let v2 = dir.path().join("victim2");
    write_file(&v1, b"dummy one");
    write_file(&v2, &vec![0u8; 20_000]);

    // Run the COPY, targeting itself plus the victims.
    let out = Command::new(&exe_copy)
        .arg("-v")
        .arg(&exe_copy)
        .arg(&v1)
        .arg(&v2)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "process crashed/failed. stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!exe_copy.exists(), "the binary's own copy must be destroyed");
    assert!(!v1.exists());
    assert!(!v2.exists());
    assert_eq!(count_files(dir.path()), 0, "everything destroyed");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("3 destroyed"), "stdout: {stdout}");
}

#[cfg(unix)]
fn send_sigint(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGINT);
    }
}
