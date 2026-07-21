# Security model, error handling & safety

What `override` guarantees, how it fails, and the invariants that protect secret
material during a run.

See also: [crypto.md](crypto.md), [resilience.md](resilience.md),
[filesystems.md](filesystems.md).

---

## Error handling & safety

- Invalid input fails clearly and non-destructively (e.g. a directory without
  `-r` is reported and skipped, siblings still processed).
- Keys, nonces, and buffer contents are never logged or written anywhere.
- SIGINT/SIGTERM are handled **everywhere**, not just in `--no-stop`: an
  interrupt lets the current chunk/pass write finish, then stops; a second
  interrupt aborts immediately.
- Exit codes: `0` success, `1` one or more targets failed, `2` fatal setup error
  (e.g. bad `--source`), `130` forced abort on second interrupt.

---

## Security invariants

These hold on every code path, including under `--verbose`:

- **Secret material never leaves memory.** Keys, nonces, and buffer contents are
  never logged, printed, or written to disk. Verbose logging emits only paths,
  phase names, pass numbers, byte lengths, and the byte-source kind.
- **Keys are scrubbed immediately after use** with `zeroize` (volatile writes +
  a compiler fence, so the scrub survives `lto = true` / `opt-level = 3`), and
  working buffers are zeroized after each pass. See [crypto.md](crypto.md).
- **The process is made non-dumpable** (`prctl(PR_SET_DUMPABLE, 0)` on Linux,
  set right after any re-exec) so the in-flight key and plaintext chunks cannot
  be captured by a same-user core dump, `ptrace`, or `/proc/<pid>/mem` while the
  run is in progress. This is best-effort defense-in-depth; buffers are not
  `mlock`ed, so it does not defend against an adversary who can read swap or the
  raw RAM.
- **Randomness is cryptographic.** Overwrite and key bytes come from the OS
  CSPRNG (`getrandom`/`OsRng`) unless you explicitly pass a `--source` file
  (which is only as unpredictable as its contents — discouraged for serious use).
- **Writes are real and durable.** Every pass uses real `write` syscalls the
  compiler cannot elide, followed by `flush()` + `sync_all()` (`fsync`).
- **Targets cannot be redirected mid-run.** Symlinks are skipped at scan time,
  and every subsequent open re-opens the target with `O_NOFOLLOW` and re-checks
  the opened inode (device + inode number) against the identity recorded during
  the scan, aborting the target on any mismatch. The rename and unlink run
  relative to a held parent-directory fd (`renameat`/`unlinkat`), so a local
  attacker who can write in the containing directory cannot swap a path
  component (or the file itself) for a symlink between passes to steer
  `override`'s destructive writes onto another file (closes a symlink-follow /
  TOCTOU race). This is Unix-only surface, matching the project's platform
  scope.

---

## What crypto-shredding does and does not promise

Crypto-shredding ([crypto.md](crypto.md)) makes the *ciphertext* it writes
cryptographically unrecoverable the moment the key is discarded. But `override`
encrypts data that **already exists as plaintext on disk**, so this only assures
destruction when writing the ciphertext back **physically overwrites the
plaintext blocks**:

- **Where a logical overwrite reaches the original physical block** (ext4/xfs on
  non-remapped media) the crypto-shred pass is effective, and it is a genuine
  extra layer over the raw overwrites.
- **Where it does not** — SSD flash-translation layers, copy-on-write /
  log-structured / snapshotted filesystems (btrfs, ZFS) — the write can be
  redirected to freshly allocated blocks, leaving the original plaintext intact
  regardless of the discarded key. There the in-place crypto-shred has the
  **same physical limitation as the overwrite passes**; it is **not** a bypass
  for those media (see [filesystems.md](filesystems.md)). `override` prints a
  runtime warning when it detects such a filesystem.

Treat crypto-shred, the overwrites, the rename, and the delete as
**defense-in-depth layers**, none of which is a primary guarantee on remapped
storage. For whole-disk assurance, prefer full-disk encryption from the start,
the drive's ATA/NVMe secure-erase command, or physical destruction.

---

## Self-resilience

Once running, the process survives destruction of its own on-disk executable
(including shredding itself). The mechanism and its platform scope are documented
in [resilience.md](resilience.md).
