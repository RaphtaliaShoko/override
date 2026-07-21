# Filesystems: warnings, the SSD/CoW caveat, and free-space wiping

Overwriting works only when rewriting a file's *logical* bytes rewrites the same
*physical* blocks. That assumption fails on several common storage types.
`override` warns you at runtime when it detects one, and crypto-shredding
([crypto.md](crypto.md)) covers the cases where overwriting cannot.

See also: [architecture.md](architecture.md), [security.md](security.md).

---

## Runtime filesystem warnings

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

> On the BSDs the same detection keys off the filesystem *type name*
> (`f_fstypename`, e.g. `zfs`/`tmpfs`/`nfs`) rather than Linux magic numbers.

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
