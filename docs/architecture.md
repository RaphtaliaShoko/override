# Architecture & the destruction pipeline

How `override` processes targets end to end: the phase pipeline, ordering,
recursion/symlink handling, dry-run, and the source-code layout.

See also: [crypto.md](crypto.md) (the encryption pass in detail),
[filesystems.md](filesystems.md), [resilience.md](resilience.md),
[security.md](security.md).

---

## The destruction pipeline

For each target file, the **default** pipeline runs in this order:

1. **Encryption** (`-e`, default 1) — crypto-shred (see [crypto.md](crypto.md)).
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

## Overwrite phases

- Writes are done in **1 MiB chunks** using real `write` syscalls (which the
  compiler cannot optimize away), followed by `flush()` and `sync_all()`
  (`fsync`) after **every pass** to force data past the page cache to storage.
- Random bytes come from the OS CSPRNG by default, or from a `--source` file
  read in a streaming, wrap-around fashion — one window (≤ 1 MiB) at a time with
  **bounded memory**, wrapping back to the start to cover files of any size. A
  huge file or an endless character device (e.g. `/dev/urandom`) is therefore
  streamed, not buffered. An empty source file is rejected. (`/dev/urandom` as a
  source is effectively equivalent to the default CSPRNG, just slower — prefer
  the default.)
  - ⚠️ **A custom `--source` is only as unpredictable as its contents.** A
    predictable or low-entropy source file makes the written bytes guessable and
    weakens the overwrite passes; it is **not recommended for serious security
    use** — prefer the default CSPRNG. `--help` and a runtime stderr warning both
    flag this. (The crypto-shred phase is independent of `--source`, which only
    feeds the overwrite passes — though on CoW/SSD it carries the same
    physical-storage caveat, see [filesystems.md](filesystems.md).)
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
