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
- **Randomness is cryptographic.** Overwrite and key bytes come from the OS
  CSPRNG (`getrandom`/`OsRng`) unless you explicitly pass a `--source` file
  (which is only as unpredictable as its contents — discouraged for serious use).
- **Writes are real and durable.** Every pass uses real `write` syscalls the
  compiler cannot elide, followed by `flush()` + `sync_all()` (`fsync`).

---

## What crypto-shredding does and does not promise

Crypto-shredding ([crypto.md](crypto.md)) makes the plaintext cryptographically
unrecoverable the moment the key is discarded — this is the guarantee that holds
even on SSDs and copy-on-write filesystems where physical overwriting cannot be
promised (see [filesystems.md](filesystems.md)). The overwrite/rename/delete
phases are **defense-in-depth** against implementation slips and metadata leakage,
not the primary guarantee.

For whole-disk assurance, prefer full-disk encryption from the start, the drive's
ATA/NVMe secure-erase command, or physical destruction.

---

## Self-resilience

Once running, the process survives destruction of its own on-disk executable
(including shredding itself). The mechanism and its platform scope are documented
in [resilience.md](resilience.md).
