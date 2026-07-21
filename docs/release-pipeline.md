# The release pipeline

[`.github/workflows/release.yml`](../.github/workflows/release.yml) builds the
**static (musl) release binaries**, signs them with the project's minisign key,
and publishes them to a GitHub Release — producing exactly the assets that
[`install.sh`](installer.md) downloads and verifies.

Why static musl: a fully static binary has no shared libraries that could be
unmapped while the filesystem around it is wiped, which is what lets `override`
finish even while destroying its own environment (see
[resilience.md](resilience.md)).

---

## What it produces

For a tag `vX.Y.Z`, the release gets:

| Asset | Purpose |
|---|---|
| `override-x86_64-linux`, `override-aarch64-linux` | static binaries |
| `override-<arch>-linux.minisig` | minisign signature (prehashed / `ED`) |
| `override_release_minisign.pub` | public key (redundant convenience copy) |
| `SHA256SUMS` | informational checksums |

The asset names and the signature scheme are exactly what `install.sh` expects,
so `./install.sh --version vX.Y.Z` downloads and verifies them with no extra
configuration.

## Triggers

- **Tag push** `vX.Y.Z` — builds, signs, and publishes the release.
- **Manual** (`workflow_dispatch`) — builds and uploads the binaries as workflow
  artifacts. It only signs/publishes a release when run with `sign=true` (and the
  signing secrets present), so `sign=false` is a safe dry run that needs no
  secrets.

## How the build works

Two matrix jobs build `x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl` with `cargo build --release --locked`. The crate has
no C dependencies, so the aarch64 target is cross-linked by rustc's bundled
`rust-lld` (`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld`) — no
external cross toolchain, no `cross`/Docker. The x86_64 binary is smoke-tested
(`--version`, `--dry-run`) on the runner before release.

Only official `actions/*` actions (`checkout`, `upload-artifact`,
`download-artifact`) plus the runner's preinstalled `rustup` and `gh` are used —
no third-party actions in the trust path.

## Signing

The release job writes the secret key to a file (`umask 077`, shredded on exit),
then signs each binary with `minisign -S -H` — `-H` forces the **prehashed
(`ED`)** variant that `install.sh`'s OpenSSL fallback verifier expects. A trusted
comment records the tag/arch and is covered by minisign's global signature. Every
signature is then **self-verified against `override_release_minisign.pub`** before
publishing, so a wrong or rotated key fails the release instead of shipping bad
signatures.

## Required secrets

Set these under **Settings → Secrets and variables → Actions**:

| Secret | Value |
|---|---|
| `MINISIGN_SECRET_KEY` | full contents of the minisign secret-key file (the `untrusted comment:` line plus the key line) |
| `MINISIGN_PASSWORD` | the key's password (empty string if the key has none) |

The signing key **must** correspond to the public key embedded in `install.sh`
(key id `BF7A2618AF8CEAE9` — the body of `override_release_minisign.pub`).
A mismatch makes every `install.sh` verification fail closed. Generate the
keypair once with `minisign -G`; the public key is already committed, so only the
two secrets above need to be added.

## Cutting a release

```sh
# bump Cargo.toml version, commit, then:
git tag v1.2.1
git push origin v1.2.1
```

The workflow builds, signs, and publishes automatically. To rehearse the build
without publishing, run the workflow manually with `sign=false` and inspect the
uploaded artifacts.
