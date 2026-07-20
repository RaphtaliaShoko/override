# `override` — secure file destruction with crypto-shredding and self-resilience

`override` is a command-line tool (written in Rust) that securely destroys files
and directories so their content cannot be recovered. It is inspired by GNU
`shred`, but adds:

- a **crypto-shredding** phase (encrypt in place with a fresh key, then discard
  the key so the plaintext is cryptographically unrecoverable),
- a **configurable multi-pass pipeline** (encryption / random / null / random),
- **configurable renaming** before deletion,
- an **infinite-loop mode** (`--no-stop`),
- a **dry-run** preview (`--dry-run`) that shows the plan without touching data,
- **read-back verification** of the crypto-shred pass (on by default),
- **runtime filesystem warnings** for copy-on-write/volatile storage,
- a **progress bar with ETA** for large files,
- **free-space wiping** (`--wipe-free`) to scrub remnants of already-deleted
  files, and
- **self-resilience**: once running, the process completes even if its own
  on-disk executable is deleted or overwritten — including when it shreds
  itself.

> ⚠️ **This tool permanently destroys data.** There is no undo. Test on
> disposable files first.

---

## Install (prebuilt binary)

The quickest way to install a released version system-wide is the `install.sh`
script, which downloads the prebuilt binary for your architecture (`x86_64` or
`aarch64`) from the GitHub Releases:

```sh
# install the default version to /usr/local/bin (uses sudo if needed)
./install.sh

# install a specific version, or into a custom prefix
./install.sh --version v1.0.0 --prefix ~/.local/bin

# preview what would happen without changing anything (also checks the URLs)
./install.sh --dry

# uninstall
./install.sh --remove
```

Every download is cryptographically verified before it is installed. The script
checks the release's minisign signature (`override-<arch>-linux.minisig`) against
the project's **public key embedded in `install.sh` itself** — never a key
downloaded at install time. That embedded key (also published as
`override_release_minisign.pub`, and carried in the script's git history) is the
trust anchor: an attacker who compromised the GitHub release still could not
forge an accepted binary without also rewriting the key across every historical
commit. A bad or missing signature aborts the install (fail-closed).

Verification uses the [`minisign`](https://jedisct1.github.io/minisign/) tool
when it is installed. If it is **not**, the script does not silently improvise —
it asks how to proceed:

1. use the script's built-in OpenSSL (Ed25519 + BLAKE2b) verifier — a
   re-implementation of minisign verification, handy when you can't install
   minisign;
2. abort so you can install minisign yourself and re-run (recommended); or
3. skip verification, which requires typing an explicit acknowledgement.

With no terminal available (CI, cron, `curl … | bash` with no tty) it fails
closed and aborts. Pass `--insecure-skip-verify` to skip verification up front
without a prompt — strongly discouraged.

Re-running the script simply installs over the existing binary, so it doubles as
the upgrade/downgrade path. Only Linux on `x86_64`/`aarch64` is supported.

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
| | `--dry-run` | — | off | Preview what would be destroyed (honoring `-r` and symlink skips) without touching anything. A missing/invalid target still exits `1`. |
| `-p` | `--prompt` | — | off | Read target paths from stdin (one per line, blank line or EOF to finish) instead of the command line, so the names of destroyed files are never recorded in your shell history. Command-line paths are still processed. |
| `-r` | `--recursive` | — | off | Recurse into directories. Without it, a directory argument is a reported error. |
| `-e` | `--encryption` | `N` | `1` | Encryption (crypto-shred) passes. `0` disables. |
| `-i` | `--iterations` | `N` | `3` | Random-overwrite passes (applied in **each** of the two random rounds). `0` disables. |
| `-n` | `--null` | `N` | `1` | Zero-fill passes. `0` disables. |
| | `--no-verify` | — | off | Skip read-back verification of the encryption pass (faster; not recommended for serious use — verification is on by default). |
| `-s` | `--source` | `PATH` | CSPRNG | File to use as the byte source for overwrites (streamed, wrapping). ⚠️ predictable sources weaken the overwrite passes — prefer the CSPRNG. |
| `-u` | `--rename` | `N` | `1` | Random renames before deletion. `0` disables renaming (still deletes). |
| `-o` | `--order` | `sequential\|batch` | `sequential`¹ | Multi-file processing order. |
| | `--no-stop` | — | off | Emergency loop: crypto-shred + rename every target up front, then loop random→null→random until interrupted, then delete. |
| | `--wipe-free` | `PATH` | — | Wipe the **free space** of the filesystem containing `PATH` instead of destroying files. Cannot be combined with file targets. ⚠️ temporarily fills the volume to 100%. |
| `-h` | `--help` | — | | Help. |
| `-V` | `--version` | — | | Version. |

¹ `--order` defaults to `sequential`, **except** under `--no-stop`, where it
defaults to `batch` (an explicit `-o sequential`/`-o batch` always wins).

A **progress bar with rate and ETA** is shown automatically for the destruction
pipeline when stderr is an interactive terminal; it is suppressed under
`--verbose` (which logs each pass instead), under `--no-stop`, and whenever
output is piped, so scripts and logs stay clean.

### Examples

```sh
override secret.txt                      # default pipeline on one file
override -v -r ./olddir                  # recursive, verbose
override -e 2 -i 3 -n 1 a.bin b.bin      # 2 encryption, 3 random, 1 null pass
override -i 0 -e 0 -n 3 log.txt          # null-only wipe
override -s /dev/urandom big.img         # explicit byte source
override --no-stop -u 5 target.dat       # emergency: crypto-shred+rename now, loop, delete on Ctrl-C
override -o batch *.log                  # batch order across many files
override -p                              # type paths interactively (kept out of shell history)
printf '%s\n' secret.txt >> ~/list; override -p < ~/list   # feed paths via stdin
override --dry-run -r ./olddir           # preview the plan, destroy nothing
override --no-verify huge.img            # skip read-back verification for speed
override --wipe-free /mnt/scratch        # scrub free space of a volume
```

> **Keeping filenames out of your history.** A normal invocation such as
> `override secret.txt` records `secret.txt` in your shell's history file, so the
> name of the destroyed file stays visible afterwards. Run `override -p` and type
> (or pipe) the path on stdin instead: the path is never an argument, so it is
> never written to history.

---

## The destruction pipeline

For each target file, the **default** pipeline runs in this order:

1. **Encryption** (`-e`, default 1) — crypto-shred.
2. **Random overwrite, round A** (`-i`, default 1).
3. **Null overwrite** (`-n`, default 1).
4. **Random overwrite, round B** (`-i`, default 1).
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

`encryption=1, iterations=1, null=1, rename=1, order=sequential`. With defaults a
file undergoes: 1 encryption + 1 random + 1 null + 1 random + 1 rename + delete.

### Order: sequential vs batch

- **sequential** (default): the entire pipeline runs on one file before the next
  file is touched.
- **batch**: phase 1 (encryption) runs on *all* files, then phase 2 on all
  files, etc., finishing with rename+delete for all files. Useful so that no
  single file is fully processed before the others begin.

`--order` defaults to `sequential`, except under `--no-stop` where it defaults to
`batch` (see below); an explicit `-o` always wins.

### `--no-stop`

Built for an **emergency where you may not be able to press Ctrl-C** (the process
could be killed or the machine powered off instead). The protections are ordered
so that even a hard kill that never reaches the delete step still leaves the data
unreadable and unidentifiable:

1. **Encrypt (crypto-shred) every target** — content is unrecoverable once the
   key is discarded.
2. **Rename every target** to a random name — the original filename is gone.
3. **Then loop** random→null→random over the targets until interrupted.
4. On interrupt, **delete** the (already renamed) targets.

Steps 1–2 run **once, up front**. Because `--no-stop` defaults to **batch** order,
the encrypt pass covers *all* targets before the lengthy looping begins, so an
early kill has crypto-shredded the whole set — not just the first file. (Pass
`-o sequential` to encrypt+rename each file fully before the next instead.)

On the **first** SIGINT/SIGTERM the current write finishes safely (no half-written
buffer), the loop stops, and the tool proceeds to delete the targets. A **second**
interrupt forces immediate termination (exit code 130).

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
  disk, logged, or printed — not even under `--verbose`.** `zeroize` performs
  **volatile writes with a compiler fence**, so the scrub is *not* elided even
  under the release profile (`lto = true`, `opt-level = 3`) — that is precisely
  why the crate is used instead of a plain assignment the optimizer could remove.
  A unit test (`zeroize_actually_scrubs_key_material`) locks this contract.

- **Read-back verification (default on).** After each ciphertext chunk is
  written, it is read back and compared against what was written *before* the
  loop advances. If a write silently did not land (a short write, a lying
  filesystem, or a logic error), the pass fails loudly rather than letting the
  file be treated as a completed crypto-shred. This is a page-cache-level
  read-back — distinct from, and cheaper than, the end-of-pass `fsync`. Disable it
  with `--no-verify` if you need the speed (not recommended for serious use).

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
  - ⚠️ **A custom `--source` is only as unpredictable as its contents.** A
    predictable or low-entropy source file makes the written bytes guessable and
    weakens the overwrite passes; it is **not recommended for serious security
    use** — prefer the default CSPRNG. `--help` and a runtime stderr warning both
    flag this. (Crypto-shredding still applies regardless of the source.)
- Null passes write zero bytes.

---

## Renaming phase

Each rename pass moves the file to a fresh, random, lowercase-alphanumeric name
in the **same directory**. Following `shred -u`, successive passes use
**progressively shorter** names to erase length information from directory
entries, before the final unlink. `-u 0` skips renaming but still deletes.

After the unlink, `override` **fsyncs the parent directory** so the removal (and
the renames) are durably persisted — a crash immediately afterwards cannot leave
the directory entry behind. This is best-effort: the file is already gone by that
point, so a failing directory fsync is logged under `--verbose` but does not mark
the file as failed.

---

## Dry run (`--dry-run`)

`--dry-run` walks the targets exactly like a real run — honoring `--recursive`
and the symlink-skip rules — and prints, for each file, the pipeline that *would*
be applied (e.g. `encrypt×1 → random×3 → null×1 → random×3 → rename×1 → delete`),
**without opening anything for writing**. A missing or invalid target is still
reported and still yields exit code `1`, so a dry run is a faithful preview of
what a real run would do. Given the tool's blast radius, running `--dry-run`
first is recommended whenever a glob or `-r` is involved.

---

## Filesystem warnings

Before doing any work, `override` checks the filesystem behind each target (via
`statfs`) and prints a one-line **stderr warning** — once per distinct
filesystem — when logical overwrites are unlikely to reach the original physical
blocks:

- **copy-on-write / log-structured** (btrfs, ZFS, overlayfs): overwrite passes
  may land in freshly allocated blocks, leaving the originals intact;
- **volatile** (tmpfs): contents never reach stable storage;
- **network** (NFS): the physical media is remote and out of the tool's control.

Crypto-shredding still protects the data in every case, but the warning tells you
when the overwrite phases are not guaranteed effective — catching users who did
not read the SSD/CoW caveat below. Ordinary filesystems (ext4, xfs, …) are
silent.

---

## Free-space wiping (`--wipe-free <PATH>`)

`override --wipe-free /some/dir` scrubs the **unused space** of the filesystem
that hosts `/some/dir`, so that remnants of files deleted *before* `override` ever
ran cannot be recovered from the free blocks. It:

1. creates a single hidden fill file on that filesystem,
2. writes random data (`-i` passes) then zeros (`-n` passes) to it until the
   volume reports `ENOSPC` (full), fsyncing each pass, and
3. always removes the fill file afterwards (even on error or Ctrl-C) and fsyncs
   the directory.

`--source` and the pass counts (`-i`, `-n`) apply as usual. ⚠️ This **temporarily
fills the volume to 100%** — do not point it at a system/root filesystem. It
scrubs free space only: it does **not** reach slack inside still-allocated blocks
or filesystem metadata/journals, and — like all overwrite methods — is ineffective
on CoW filesystems and SSD-remapped storage. Combine with `--dry-run` to see what
it would do without filling anything.

---

## Self-resilience (critical requirement)

Once `override` starts, nothing that happens to its on-disk executable can crash
it or stop it — including deliberately shredding its own binary.

**Mechanism (Linux):** at startup, before touching any target, the process
copies its own executable image (`/proc/self/exe`) into an anonymous,
memory-backed file via `memfd_create(2)` and **re-executes itself from that
memfd** with `fexecve(2)` (an `execveat` on the memfd with `AT_EMPTY_PATH`).
After the re-exec the running image is backed entirely by the anonymous memfd, so
unlinking, truncating, or overwriting the original on-disk file cannot unmap code
pages or trigger `SIGBUS`.

**Loop guard (belt and suspenders).** Two independent checks stop the re-exec
from recurring forever (each recursion would allocate a fresh memfd):

1. a guard environment variable (`OVERRIDE_MEMFD_REEXEC`) set on the child — the
   fast path, no syscall; and
2. an **env-independent** check: after re-exec, `/proc/self/exe` resolves to a
   `/memfd:…` target, which the process detects and refuses to re-exec on.

The env var alone is not sufficient — a sandbox or CI that sanitizes the
environment could strip it between the re-exec and the child's startup, and the
child would then loop. The `/proc/self/exe` check cannot be stripped, so it
breaks the loop even when the env var is gone. (Under `--verbose` the resident
child logs `running from in-memory image`.)

This is combined with the **static musl** build so there are also no shared
objects to lose. The memfd step is **best-effort and non-critical**: if it is
unavailable it logs a note under `--verbose` and continues, relying on the static
image already being resident — see the design note below.

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
- **Default counts**: `-e 1 -i 1 -n 1 -u 1` — with crypto-shredding as the
  primary defense, a single random pass suffices; raise `-i` for extra overwrite
  rounds on magnetic media.
- **In-place, same-length encryption** writing ciphertext-without-tag, chosen so
  the encryption phase truly overwrites the original blocks (important on HDDs)
  rather than reallocating via a temp-file rename.
- **Self-resilience via memfd re-exec + static musl** (both, belt and
  suspenders) rather than relying on page residency alone. The memfd re-exec is
  **defense-in-depth, not a hard dependency**: it protects the *dynamically*
  linked build and the case where `/proc/self/exe`'s path is unlinked mid-run,
  but the static musl build alone already keeps its pages resident. A memfd
  failure therefore **degrades gracefully** (logged under `--verbose`) instead of
  breaking the tool — the re-exec is best-effort by design.
- **Symlinks are always skipped** (never followed, never destroyed) for safety.
- **Directories are not removed**, only the regular files inside them.
- **Chunk size 1 MiB** for both encryption and overwrite I/O.

---

## Project layout

```
src/
  main.rs         binary entry: re-exec, signal install, run / wipe-free dispatch
  lib.rs          library root + shared constants
  cli.rs          clap CLI definition (+ arg-parsing tests)
  pipeline.rs     target collection, phase ordering, sequential/batch/no-stop,
                  dry-run, progress + verify wiring
  crypto.rs       in-place ChaCha20-Poly1305 crypto-shred pass + read-back verify
  overwrite.rs    random/null overwrite passes, rename, delete, dir fsync (+ tests)
  source.rs       CSPRNG / source-file byte source (+ tests)
  signals.rs      SIGINT/SIGTERM interrupt state
  resilience.rs   memfd_create + fexecve self-resilience
  fswarn.rs       statfs-based copy-on-write / volatile filesystem warnings
  progress.rs     indicatif progress bar / spinner wrapper
  freespace.rs    free-space wiping (--wipe-free)
tests/
  integration.rs  end-to-end, recursive/batch, no-stop, self-resilience,
                  dry-run, no-verify, wipe-free
```

## License

MIT.
