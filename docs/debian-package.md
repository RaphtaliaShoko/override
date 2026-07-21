# The Debian package (`.deb`)

For Debian/Ubuntu and other `apt`-based systems, `override` can be installed as a
native `.deb` package. Unlike [`install.sh`](installer.md) — which downloads a
signed release binary from GitHub — the `.deb` is **built from this source tree**
and integrates with `dpkg`/`apt`: it registers with the package database, ships a
man page and shell completion, and can be cleanly removed or upgraded.

See also: [installer.md](installer.md) (the signed-binary installer) and the
[README](../README.md) quick-start.

---

## Building the package

```sh
./packaging/build-deb.sh
# → dist/override-tool_<version>_<arch>.deb
```

Requirements: a Rust toolchain (`cargo`), `dpkg-deb`, and `dpkg-dev` (for
`dpkg-architecture` / `dpkg-shlibdeps`). The script:

- compiles the release binary (`cargo build --release`);
- reads the version from `Cargo.toml` and the target architecture from
  `dpkg-architecture` (so it also works when cross-building);
- assembles a policy-compliant tree (see below), computing `Installed-Size` and
  deriving the library `Depends` with `dpkg-shlibdeps` (falling back to a
  conservative `libc6`/`libgcc-s1` set);
- emits the `.deb` into `dist/` and prints its `--info` and `--contents`.

Output directory can be overridden: `./packaging/build-deb.sh --outdir /path`.

## Installing and removing

```sh
sudo apt install ./dist/override-tool_1.2.1-1_amd64.deb   # resolves dependencies
# or, without dependency resolution:
sudo dpkg -i ./dist/override-tool_1.2.1-1_amd64.deb

sudo apt remove override-tool                             # uninstall
```

Re-installing a newer `.deb` is the upgrade path. The binary package is named
`override-tool` (matching the crate; `override` is a Cargo/Debian-unfriendly
name), while the installed command is `override`.

## Package contents

| Path | Purpose |
|---|---|
| `/usr/bin/override` | the binary (stripped, release build) |
| `/usr/share/man/man1/override.1.gz` | man page (`man override`) |
| `/usr/share/bash-completion/completions/override` | bash tab-completion |
| `/usr/share/doc/override-tool/` | README, all `docs/*.md` (gzipped), copyright, Debian changelog |

## Package metadata

- **Package:** `override-tool` · **Section:** `utils` · **Priority:** `optional`
- **Depends:** computed from the binary — typically `libc6 (>= 2.34)` and
  `libgcc-s1`.
- **Maintainer / Homepage:** taken from the project.

The source files live under [`packaging/`](../packaging): the build script,
`override.1` (man page), `override.bash-completion`, `copyright`
(machine-readable, MIT), and the Debian `changelog`.

## Standards compliance

The package is [`lintian`](https://lintian.debian.org/)-clean apart from
`initial-upload-closes-no-bugs`, which only applies to uploads into the official
Debian archive (it expects an ITP bug reference) and is not relevant to a
self-distributed package.

## Which installer should I use?

- **`.deb`** — you are on a Debian/Ubuntu system, want `apt`/`dpkg` integration
  (clean upgrades/removal, a man page, completion), and are building from source.
- **[`.rpm`](rpm-package.md)** — the equivalent for Fedora/RHEL/openSUSE.
- **[`install.sh`](installer.md)** — you want the prebuilt, **cryptographically
  signed** release binary from GitHub without a Rust toolchain, on any Linux
  distribution.
