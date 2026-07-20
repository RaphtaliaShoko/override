# `override` — secure file destruction with crypto-shredding and self-resilience

`override` is a command-line tool (written in Rust) that securely destroys files
and directories so their content cannot be recovered. It is inspired by GNU
`shred`, but adds:

- a **crypto-shredding** phase (encrypt in place with a fresh key, then discard
  the key so the plaintext is cryptographically unrecoverable),
- a **configurable multi-pass pipeline** (encryption / random / null / random),
- **configurable renaming** before deletion,
- an **infinite-loop mode** (`--no-stop`), and
- **self-resilience**: once running, the process completes even if its own
  on-disk executable is deleted or overwritten — including when it shreds
  itself.

> ⚠️ **This tool permanently destroys data.** There is no undo. Test on
> disposable files first.

---

## Build

Requires a Rust toolchain (tested with Rust 1.97).

### Standard build (dynamically linked, this host's libc)

```sh
cargo build --release
# binary at target/release/override
```

### Recommended: static build (musl) for maximum self-resilience

A statically linked binary has **no external shared libraries** that could be
unmapped or removed while the filesystem around it is being wiped:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# fully static binary at target/x86_64-unknown-linux-musl/release/override
file target/x86_64-unknown-linux-musl/release/override
#   => ... static-pie linked, stripped
```

### Test

```sh
cargo test                 # unit + integration tests (uses the dynamic build)
```

---

## Usage

```
override [OPTIONS] <PATH>...
```

| Short | Long | Arg | Default | Description |
|---|---|---|---|---|
| `-v` | `--verbose` | — | off | Print progress for every file/phase/pass. |
| `-r` | `--recursive` | — | off | Recurse into directories. Without it, a directory argument is a reported error. |
| `-e` | `--encryption` | `N` | `1` | Encryption (crypto-shred) passes. `0` disables. |
| `-i` | `--iterations` | `N` | `3` | Random-overwrite passes (applied in **each** of the two random rounds). `0` disables. |
| `-n` | `--null` | `N` | `1` | Zero-fill passes. `0` disables. |
| `-s` | `--source` | `PATH` | CSPRNG | File to use as the byte source for overwrites (streamed, wrapping). |
| `-u` | `--rename` | `N` | `1` | Random renames before deletion. `0` disables renaming (still deletes). |
| `-o` | `--order` | `sequential\|batch` | `sequential` | Multi-file processing order. |
| | `--no-stop` | — | off | Loop encrypt→random→null→random until interrupted, then rename+delete. |
| `-h` | `--help` | — | | Help. |
| `-V` | `--version` | — | | Version. |

### Examples

```sh
override secret.txt                      # default pipeline on one file
override -v -r ./olddir                  # recursive, verbose
override -e 2 -i 3 -n 1 a.bin b.bin      # 2 encryption, 3 random, 1 null pass
override -i 0 -e 0 -n 3 log.txt          # null-only wipe
override -s /dev/urandom big.img         # explicit byte source
override --no-stop -u 5 target.dat       # loop; on Ctrl-C, 5 renames + delete
override -o batch *.log                  # batch order across many files
```

---

## The destruction pipeline

For each target file, the **default** pipeline runs in this order:

1. **Encryption** (`-e`, default 1) — crypto-shred.
2. **Random overwrite, round A** (`-i`, default 3).
3. **Null overwrite** (`-n`, default 1).
4. **Random overwrite, round B** (`-i`, default 3).
5. **Rename** (`-u`, default 1) to random name(s).
6. **Delete** (unlink).

Any phase whose count is `0` is skipped. After deletion the file is gone; the
directory that contained it is left in place.

### `--iterations` semantics (phase reuse)

Phases 2 and 4 are both random-overwrite phases sharing one implementation. This
tool interprets `--iterations=N` as **N passes in round A *and* N passes in round
B** (so `-i 3` performs 3 + 3 = 6 random passes total, straddling the null
phase). This is stated in `--help` and is the behavior the tests assert.

### Default pass counts

`encryption=1, iterations=3, null=1, rename=1, order=sequential`. With defaults a
file undergoes: 1 encryption + 3 random + 1 null + 3 random + 1 rename + delete.

### Order: sequential vs batch

- **sequential** (default): the entire pipeline runs on one file before the next
  file is touched.
- **batch**: phase 1 (encryption) runs on *all* files, then phase 2 on all
  files, etc., finishing with rename+delete for all files. Useful so that no
  single file is fully processed before the others begin.

### `--no-stop`

Instead of running once, the encrypt→random→null→random cycle repeats forever on
all targets. On the **first** SIGINT/SIGTERM the current write finishes safely
(no half-written buffer), the loop stops, and the tool proceeds to rename+delete
so the files are still properly destroyed. A **second** interrupt forces
immediate termination (exit code 130).

---

## Encryption phase (crypto-shredding) — how it works

- Scheme: **ChaCha20-Poly1305** (AEAD) via the audited `chacha20poly1305` crate.
- Each pass generates a fresh **256-bit key** from the OS CSPRNG (`getrandom`),
  builds the cipher, and immediately zeroizes the raw key bytes.
- The file is processed in **1 MiB chunks** (bounded memory for any file size).
  Each chunk is authenticated-encrypted with a per-chunk counter nonce (unique
  per key, since every pass uses a new key).
- Because ChaCha20 is a stream cipher, the ciphertext is the **same length** as
  the plaintext, so it is written back **strictly in place** — the original
  plaintext blocks are physically rewritten, not reallocated to new blocks. The
  16-byte authentication tag is intentionally **discarded** together with the
  key (the data is never meant to be decrypted again; using an AEAD scheme still
  satisfies the "modern authenticated encryption" requirement and gives a clean,
  well-reviewed primitive).
- The key is wrapped in `zeroize::Zeroizing` / scrubbed with `.zeroize()`, and
  the working buffer is zeroized after each pass. **The key is never written to
  disk, logged, or printed — not even under `--verbose`.**

Once the key is gone the plaintext is already cryptographically inaccessible; the
overwrite phases are defense-in-depth against implementation slips and metadata
leakage.

---

## Overwrite phases — how they work

- Writes are done in **1 MiB chunks** using real `write` syscalls (which the
  compiler cannot optimize away), followed by `flush()` and `sync_all()`
  (`fsync`) after **every pass** to force data past the page cache to storage.
- Random bytes come from the OS CSPRNG by default, or from a `--source` file
  read in a streaming, wrap-around fashion (loaded once, repeated to cover files
  of any size). An empty source file is rejected.
- Null passes write zero bytes.

---

## Renaming phase

Each rename pass moves the file to a fresh, random, lowercase-alphanumeric name
in the **same directory**. Following `shred -u`, successive passes use
**progressively shorter** names to erase length information from directory
entries, before the final unlink. `-u 0` skips renaming but still deletes.

---

## Self-resilience (critical requirement)

Once `override` starts, nothing that happens to its on-disk executable can crash
it or stop it — including deliberately shredding its own binary.

**Mechanism (Linux):** at startup, before touching any target, the process
copies its own executable image (`/proc/self/exe`) into an anonymous,
memory-backed file via `memfd_create(2)` and **re-executes itself from that
memfd** with `fexecve(2)` (an `execveat` on the memfd with `AT_EMPTY_PATH`). A
guard environment variable (`OVERRIDE_MEMFD_REEXEC`) prevents an infinite
re-exec loop. After the re-exec the running image is backed entirely by the
anonymous memfd, so unlinking, truncating, or overwriting the original on-disk
file cannot unmap code pages or trigger `SIGBUS`.

This is combined with the **static musl** build so there are also no shared
objects to lose. The memfd step is **best-effort**: if it is unavailable it logs
a note under `--verbose` and continues, relying on the static image already being
resident.

**Platform scope / limitations:** the memfd+`fexecve` path is Linux-only
(`memfd_create` ≥ Linux 3.17, `execveat` ≥ 3.19). On non-Linux platforms the
re-exec step is skipped; use a static build for equivalent robustness where the
OS keeps mapped executable pages resident after unlink. The tool targets Linux.

An automated integration test (`self_resilience_shreds_own_binary`) copies the
binary into a temp dir, runs it against dummy files **plus its own copy**, and
asserts it completes and destroys everything.

---

## Multi-file / recursive / symlink handling

- Multiple file and directory arguments are accepted in one invocation.
- `--recursive` walks directories with `walkdir` (**symlinks are not followed**),
  processing every regular file found.
- **Symlinks are never followed and never destroyed** — whether passed directly
  or encountered during a walk — so the tool cannot be tricked into destroying
  files outside the intended tree. Such entries are reported and skipped.
- Per-target errors (missing file, permission denied, directory without `-r`) are
  reported and the tool **continues with the remaining targets**; the process
  exits non-zero if any target failed.

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

## ⚠️ Caveat: SSDs and copy-on-write filesystems

Overwriting a file's logical contents does **not** guarantee the original
**physical** bytes are gone on:

- **SSDs / flash** — wear-leveling and over-provisioning mean writes often land
  on different physical cells; old cells may retain data until garbage-collected.
- **Copy-on-write filesystems** (btrfs, ZFS, and snapshotted volumes) — a write
  allocates new blocks and may keep the old ones (e.g. in snapshots).
- **Journaling, caching layers, RAID, virtualized/network storage** — may retain
  copies.

On such systems, overwrite-based tools (including `shred` and `override`) cannot
promise physical erasure. This is *why* `override` leads with crypto-shredding:
discarding the key renders the content unrecoverable **regardless** of where the
ciphertext physically lives. For whole-disk guarantees, prefer full-disk
encryption from the start, the drive's secure-erase (ATA/NVMe) command, or
physical destruction.

---

## Design decisions (where the spec left room for judgment)

- **`--iterations` = N per round** (2 and 4 each get N passes), documented above.
- **Default counts**: `-e 1 -i 3 -n 1 -u 1` (3 mirrors `shred`'s default).
- **In-place, same-length encryption** writing ciphertext-without-tag, chosen so
  the encryption phase truly overwrites the original blocks (important on HDDs)
  rather than reallocating via a temp-file rename.
- **Self-resilience via memfd re-exec + static musl** (both, belt and
  suspenders) rather than relying on page residency alone.
- **Symlinks are always skipped** (never followed, never destroyed) for safety.
- **Directories are not removed**, only the regular files inside them.
- **Chunk size 1 MiB** for both encryption and overwrite I/O.

---

## Project layout

```
src/
  main.rs         binary entry: re-exec, signal install, run
  lib.rs          library root + shared constants
  cli.rs          clap CLI definition (+ arg-parsing tests)
  pipeline.rs     target collection, phase ordering, sequential/batch/no-stop
  crypto.rs       in-place ChaCha20-Poly1305 crypto-shred pass (+ tests)
  overwrite.rs    random/null overwrite passes, rename, delete (+ tests)
  source.rs       CSPRNG / source-file byte source (+ tests)
  signals.rs      SIGINT/SIGTERM interrupt state
  resilience.rs   memfd_create + fexecve self-resilience
tests/
  integration.rs  end-to-end, recursive/batch, no-stop, self-resilience
```

## License

MIT.
