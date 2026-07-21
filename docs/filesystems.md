# Filesystems: warnings, the SSD/CoW caveat, and free-space wiping

Every in-place method works only when rewriting a file's *logical* bytes
rewrites the same *physical* blocks. That assumption fails on several common
storage types, and it fails for the **crypto-shred pass just as much as for the
overwrite passes** — because the plaintext already exists on disk, re-encrypting
it in place is no help if the write lands on new blocks and leaves the original
plaintext behind. `override` warns you at runtime when it detects such a
filesystem; on those media, use the whole-disk measures below instead of relying
on this tool.

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

On such a filesystem **none** of the in-place passes — neither the overwrites
nor the crypto-shred — is guaranteed to reach the original blocks, so the warning
tells you the tool cannot assure destruction there and points you at the SSD/CoW
caveat below. Ordinary filesystems (ext4, xfs, …) are silent.

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
promise physical erasure. **Crypto-shredding does not rescue this case:** the
plaintext is already on the media before `override` runs, and encrypting it in
place writes the ciphertext through the same redirected path, so the original
plaintext blocks can survive untouched even after the key is discarded — the
crypto-shred pass has the *same* physical limitation as the overwrite passes
here. (It was proven during the audit that on btrfs 100% of a known plaintext
marker remained recoverable after a full `override` run.) For whole-disk
guarantees, prefer full-disk encryption from the start, the drive's secure-erase
(ATA/NVMe) command, or physical destruction.

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
fills the volume to 100%**. Pointing it at the **root/system filesystem is
refused** (filling it can crash services or the machine) unless you pass
`--force`. It scrubs free space only: it does **not** reach slack inside
still-allocated blocks or filesystem metadata/journals, and — like all overwrite
methods — is ineffective on CoW filesystems and SSD-remapped storage. Combine with
`--dry-run` to see what it would do without filling anything.

> **Reserved-blocks gap.** On ext2/3/4, a percentage of blocks (default ~5%) is
> reserved for root. Running `--wipe-free` as a **non-root** user cannot allocate
> those blocks, so that fraction of the free space is **left un-wiped** — the
> scrub is silently incomplete. Run as root, or temporarily lower the reserve
> with `tune2fs -m 0 <device>` (restore it afterwards), to cover it.
