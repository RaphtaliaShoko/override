# Design decisions

Where the spec left room for judgment, these are the choices made — recorded so
they aren't "fixed" into regressions.

See also: [crypto.md](crypto.md), [architecture.md](architecture.md),
[resilience.md](resilience.md).

---

- **`--iterations` = N per round** (phases 2 and 4 each get N passes), documented
  in [architecture.md](architecture.md).
- **Default counts**: `-e 1 -i 1 -n 1 -u 1` — on non-remapped media
  crypto-shredding plus a single random pass suffices as defense-in-depth; raise
  `-i` for extra overwrite rounds on magnetic media. (No pass count assures
  destruction on SSD/CoW; see [filesystems.md](filesystems.md).)
- **In-place, same-length encryption** writing ciphertext-without-tag, chosen so
  the encryption phase overwrites the original blocks *where the filesystem
  writes in place* (ext4/xfs on non-remapped media) rather than reallocating via
  a temp-file rename. Note this does **not** overcome CoW/SSD block remapping —
  there the in-place crypto-shred has the same limitation as the overwrite
  passes ([filesystems.md](filesystems.md)).
- **AEAD tag discarded** with the key: the data is never meant to be decrypted;
  AEAD is chosen only as a well-reviewed primitive.
- **Self-resilience via memfd re-exec + static musl** (both, belt and
  suspenders) rather than relying on page residency alone. The memfd re-exec is
  **defense-in-depth, not a hard dependency**: it protects the *dynamically*
  linked build and the case where `/proc/self/exe`'s path is unlinked mid-run,
  but the static musl build alone already keeps its pages resident. A memfd
  failure therefore **degrades gracefully** (logged under `--verbose`) instead of
  breaking the tool — the re-exec is best-effort by design. See
  [resilience.md](resilience.md).
- **Platform portability:** Linux is the primary, fully-tested target; FreeBSD
  gets self-resilience feature-parity; other BSDs and macOS compile with the
  OS-specific bits as graceful no-ops. Every platform-specific path is `#[cfg]`-
  gated with a fallback, so the tool builds and runs anywhere. Windows was dropped
  (Unix-only signal/`nix` primitives, and NTFS overwrite semantics differ).
- **Symlinks are always skipped** (never followed, never destroyed) for safety.
- **Directories are not removed**, only the regular files inside them.
- **Chunk size 1 MiB** for both encryption and overwrite I/O.
- **Release verification** in `install.sh` uses a **minisign signature** checked
  against an **embedded** public key (not a bare checksum, not a downloaded key):
  a signature beats a hash, and embedding the key in git history is a trust anchor
  a release compromise cannot forge. See [installer.md](installer.md).
