# FAQ

Short answers, with links to the detailed docs.

---

**Can I recover a file after `override` destroys it?**
No. There is no undo. Crypto-shredding discards the encryption key, and the file
is then overwritten, renamed, and unlinked. Test on disposable files first.

**Does overwriting actually erase data on my SSD?**
Not necessarily — wear-leveling, over-provisioning, and copy-on-write filesystems
can leave old physical blocks intact. This is exactly why `override` leads with
crypto-shredding, which makes the plaintext unrecoverable regardless of where the
ciphertext physically lives. See [filesystems.md](filesystems.md).

**Why crypto-shred instead of just overwriting many times?**
On modern storage, "overwrite the same block N times" is not guaranteed to touch
the original physical cells. Discarding a random key is a guarantee that does not
depend on physical block placement. The overwrite passes remain as
defense-in-depth. See [crypto.md](crypto.md) and [security.md](security.md).

**How many passes should I use?**
The defaults (`-e 1 -i 1 -n 1 -u 1`) are enough for most cases because
crypto-shredding is the primary defense. Raise `-i` for extra overwrite rounds on
magnetic media. See [architecture.md](architecture.md).

**What happens if the process is killed mid-run?**
On the first SIGINT/SIGTERM the current write finishes safely and the tool moves
on to rename+delete; a second interrupt aborts immediately (exit code 130). For
emergencies where you may not be able to press Ctrl-C, use `--no-stop`, which
crypto-shreds and renames every target up front. See
[architecture.md](architecture.md#--no-stop).

**How do I keep destroyed filenames out of my shell history?**
Run `override -p` and type or pipe the paths on stdin — they are never command-line
arguments, so they are never written to history.

**Does `override` delete directories?**
No. It destroys the regular files inside them (with `--recursive`) but leaves the
directory structure in place.

**Are symlinks followed?**
Never. Symlinks are neither followed nor destroyed, so the tool cannot be tricked
into destroying files outside the intended tree.

**Is the downloaded binary safe to trust?**
`install.sh` verifies every download against a minisign signature using a public
key embedded in the script itself (and its git history), failing closed on any
mismatch. See [installer.md](installer.md).

**What is `--wipe-free` for?**
It scrubs the free space of a filesystem so remnants of files deleted *before*
`override` ran cannot be recovered from unused blocks. It temporarily fills the
volume to 100%. See [filesystems.md](filesystems.md#free-space-wiping---wipe-free-path).

**Which platforms are supported?**
Linux is the primary, fully-tested target (x86_64 / aarch64). FreeBSD has
self-resilience feature-parity and compiles cleanly; other BSDs and macOS build
with the OS-specific features as graceful no-ops. Windows is not supported. See
[resilience.md](resilience.md) and [design.md](design.md).

**Do I need the static (musl) build?**
No, but it is recommended: a fully static binary has no shared libraries that
could be unmapped while the filesystem around it is wiped, strengthening
self-resilience. See [resilience.md](resilience.md).
