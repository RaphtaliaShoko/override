# The RPM package (`.rpm`)

For Fedora/RHEL/openSUSE and other `rpm`-based systems, `override` can be
installed as a native `.rpm` package built from this source tree. It integrates
with `rpm`/`dnf`: it registers with the package database, ships a man page and
shell completion, and can be cleanly upgraded or removed.

See also: [debian-package.md](debian-package.md) (the `.deb` equivalent) and the
[README](../README.md) quick-start.

---

## Building the package

The build must run on an RPM-based host with `rpmbuild`, `cargo`, and `rust`
(e.g. `dnf install rpm-build rpmdevtools cargo rust`). From a checkout on such a
host:

```sh
./packaging/build-rpm.sh
# → dist/override-tool-<version>-<release>.<dist>.<arch>.rpm
```

The script builds a source tarball straight from the committed git tree
(`git archive`, so `target/`, `VM/`, and `dist/` are excluded) and runs
`rpmbuild -bb` against [`packaging/override-tool.spec`](../packaging/override-tool.spec).
Library dependencies (glibc, libgcc) are detected automatically by RPM's
`find-requires`. Output directory can be overridden with `--outdir DIR`.

Building on a Debian/dev machine? Run it inside a Fedora VM or container and copy
the resulting `.rpm` back into `dist/`.

## Installing and removing

```sh
sudo dnf install ./dist/override-tool-1.2.1-1.fc44.x86_64.rpm   # resolves deps
# or:
sudo rpm -i ./dist/override-tool-1.2.1-1.fc44.x86_64.rpm

sudo dnf remove override-tool                                   # uninstall
```

Installing a newer `.rpm` is the upgrade path. The package is named
`override-tool` (matching the crate), while the installed command is `override`.
A matching `-debuginfo` / `-debugsource` pair is produced alongside the main
package.

## Package contents

| Path | Purpose |
|---|---|
| `/usr/bin/override` | the binary (release build) |
| `/usr/share/man/man1/override.1.gz` | man page (`man override`) |
| `/usr/share/bash-completion/completions/override` | bash tab-completion |
| `/usr/share/doc/override-tool/` | README and all `docs/*.md` |
| `/usr/share/licenses/override-tool/LICENSE` | license (RPM `%license`) |

## Package metadata

- **Name:** `override-tool` · **License:** `MIT`
- **Requires:** auto-detected shared-library dependencies (`libc.so.6`,
  `libm.so.6`, `libgcc_s.so.1`, versioned symbols).
- The spec lives at [`packaging/override-tool.spec`](../packaging/override-tool.spec);
  the man page and completion come from [`packaging/`](../packaging).

## Standards compliance

`rpmlint` reports only two `spelling-error` entries (`unlinks`, `fsync'ing`) in
the description — false positives for correct technical terms, not packaging
defects. `rpm -V` on the installed package is clean.

## Which installer should I use?

- **`.rpm`** — Fedora/RHEL/openSUSE, want `dnf`/`rpm` integration and are building
  from source.
- **[`.deb`](debian-package.md)** — Debian/Ubuntu, want `apt`/`dpkg` integration.
- **[`install.sh`](installer.md)** — any Linux, want the prebuilt,
  **cryptographically signed** release binary without a Rust toolchain.
