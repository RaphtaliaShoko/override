# `override` — secure file destruction with crypto-shredding and self-resilience

`override` is a command-line tool (written in Rust) that securely destroys files
and directories so their content cannot be recovered. It is inspired by GNU
`shred`, but leads with **crypto-shredding** — encrypt in place with a fresh key,
then discard the key — so the plaintext is cryptographically unrecoverable even
on SSDs and copy-on-write filesystems where physical overwriting cannot be
guaranteed.

> ⚠️ **This tool permanently destroys data.** There is no undo. Test on
> disposable files first.

## Features

- **Crypto-shredding** — encrypt each file in place with a fresh 256-bit key
  (ChaCha20-Poly1305), then throw the key away.
- **Configurable multi-pass pipeline** — encryption / random / null / random.
- **Configurable renaming** before deletion (shortening names, like `shred -u`).
- **Read-back verification** of the crypto-shred pass (on by default).
- **Emergency mode** (`--no-stop`) — crypto-shred + rename everything up front,
  then loop until interrupted, for when you can't rely on pressing Ctrl-C.
- **Dry-run preview** (`--dry-run`) — see the exact plan without touching data.
- **Runtime filesystem warnings** for copy-on-write / volatile / network storage.
- **Free-space wiping** (`--wipe-free`) to scrub remnants of already-deleted files.
- **Progress bar with ETA** for large files.
- **Self-resilience** — once running, the process finishes even if its own
  on-disk executable is deleted or overwritten, including when it shreds itself.

## Install

The quickest way is `install.sh`, which downloads the prebuilt binary for your
architecture (`x86_64` or `aarch64`) from GitHub Releases. Linux only.

```sh
./install.sh                                       # default version → /usr/local/bin
./install.sh --version v1.0.0 --prefix ~/.local/bin
./install.sh --dry                                 # preview, change nothing
./install.sh --remove                              # uninstall
```

Every download is **cryptographically verified** (minisign signature against a
public key embedded in the script itself) and the install **fails closed** on any
mismatch. Full verification model and options → **[docs/installer.md](docs/installer.md)**.

On Debian/Ubuntu you can instead build a native **`.deb`** from this source tree
(integrates with `apt`/`dpkg`, ships a man page and shell completion):

```sh
./packaging/build-deb.sh                           # → dist/override-tool_<ver>_<arch>.deb
sudo apt install ./dist/override-tool_1.1.0-1_amd64.deb
```

Details → **[docs/debian-package.md](docs/debian-package.md)**.

On Fedora/RHEL/openSUSE you can build a native **`.rpm`** the same way (run on an
RPM host with `rpmbuild`/`cargo`):

```sh
./packaging/build-rpm.sh                            # → dist/override-tool-<ver>-<rel>.<arch>.rpm
sudo dnf install ./dist/override-tool-1.1.0-1.fc44.x86_64.rpm
```

Details → **[docs/rpm-package.md](docs/rpm-package.md)**.

## Build

Requires a Rust toolchain (tested with Rust 1.97).

```sh
cargo build --release                              # dynamic, this host's libc
# → target/release/override

rustup target add x86_64-unknown-linux-musl        # recommended: static binary
cargo build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/override  (no shared libs to lose)

cargo test                                         # unit + integration tests
```

A static (musl) build has no external shared libraries that could be unmapped
while the filesystem around it is wiped — see [docs/resilience.md](docs/resilience.md).

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
| `-i` | `--iterations` | `N` | `1` | Random-overwrite passes (applied in **each** of the two random rounds). `0` disables. |
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

A **progress bar with rate and ETA** is shown automatically when stderr is an
interactive terminal; it is suppressed under `--verbose`, under `--no-stop`, and
whenever output is piped.

By default each file undergoes: **encrypt → random → null → random → rename →
delete** (any phase with count `0` is skipped). The full pipeline semantics —
`--iterations` behavior, `sequential` vs `batch`, and `--no-stop` ordering — are
in **[docs/architecture.md](docs/architecture.md)**.

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
> `override secret.txt` records `secret.txt` in your shell's history file. Run
> `override -p` and type (or pipe) the path on stdin instead: the path is never an
> argument, so it is never written to history.

## Security notes

- **Crypto-shredding is the primary guarantee.** Once the random key is
  discarded the plaintext is cryptographically unrecoverable, *regardless* of
  where the ciphertext physically lives. The overwrite/rename/delete phases are
  defense-in-depth.
- ⚠️ **Overwriting alone cannot promise physical erasure** on SSDs, copy-on-write
  filesystems (btrfs, ZFS, snapshots), or journaled/RAID/network storage —
  `override` warns you at runtime when it detects such a filesystem. For
  whole-disk guarantees prefer full-disk encryption, ATA/NVMe secure-erase, or
  physical destruction. Details → [docs/filesystems.md](docs/filesystems.md).
- **Secrets never leave memory** — keys, nonces, and buffers are never logged,
  printed, or written to disk (not even under `--verbose`), and keys are zeroized
  immediately after use.
- **Safe by default** — read-back verification of the crypto-shred pass is on,
  symlinks are never followed, interrupts finish the current write before
  stopping, and the installer fails closed on a bad signature.
- Exit codes: `0` success, `1` a target failed, `2` fatal setup error, `130`
  forced abort on second interrupt.

Full model, invariants, and threat notes → **[docs/security.md](docs/security.md)**.

## Documentation

| Doc | Covers |
|---|---|
| [architecture.md](docs/architecture.md) | The destruction pipeline, ordering, `--no-stop`, dry-run, recursion/symlinks, source layout |
| [crypto.md](docs/crypto.md) | The crypto-shred (encryption) phase in detail |
| [filesystems.md](docs/filesystems.md) | Filesystem warnings, the SSD/CoW caveat, free-space wiping |
| [resilience.md](docs/resilience.md) | Self-resilience: memfd/`fexecve` re-exec and platform scope |
| [security.md](docs/security.md) | Security model, invariants, error handling, exit codes |
| [installer.md](docs/installer.md) | `install.sh` options and the signature-verification model |
| [debian-package.md](docs/debian-package.md) | Building and installing the `.deb` package |
| [rpm-package.md](docs/rpm-package.md) | Building and installing the `.rpm` package |
| [design.md](docs/design.md) | Design decisions where the spec left room for judgment |
| [faq.md](docs/faq.md) | Short answers to common questions |

## License

MIT.
