# The `install.sh` release installer

`install.sh` installs a **released** binary system-wide by downloading
`override-<arch>-linux` from the project's GitHub Releases and verifying it
cryptographically before installing. This document covers its options and the
full verification model. Only Linux on `x86_64`/`aarch64` is supported.

See also: [design.md](design.md) (why signature-over-embedded-key),
[release-pipeline.md](release-pipeline.md) (the CI that builds and signs the very
assets this script downloads), and the [README](../README.md) for the quick-start.

---

## Usage

```sh
# install the default version to /usr/local/bin (uses sudo if needed)
./install.sh

# install a specific version, or into a custom prefix
./install.sh --version v1.0.0 --prefix ~/.local/bin

# preview what would happen without changing anything (also checks the URLs)
./install.sh --dry

# uninstall
./install.sh --remove
```

### Options

| Option | Meaning |
|---|---|
| `--version <vX.Y.Z>` | Release to install (a bare `1.0.0` is normalised to `v1.0.0`). |
| `--prefix <dir>` | Install directory (default `/usr/local/bin`). |
| `--remove` | Uninstall the binary. |
| `--dry` | Print the plan and HEAD-check both the binary and `.minisig` URLs; make no changes. |
| `--insecure-skip-verify` | Skip signature verification up front, no prompt (**strongly discouraged**). Aliases: `--no-verify`, `--skip-verify`, and legacy `--no-checksum`/`--skip-checksum`. |
| `--help` | Usage. |

- **Arch autodetect** via `uname -m` → `x86_64` / `aarch64` (anything else
  errors); Linux-only.
- **Escalation:** `sudo` is used only when the nearest existing ancestor of
  `--prefix` is not writable.
- The download is verified to be an ELF binary before installing, in addition to
  the signature check.
- Re-running over an existing install is the **upgrade/downgrade** path.

---

## Signature verification (default on)

After downloading, the script verifies the binary against the release's minisign
signature (`override-<arch>-linux.minisig`).

### Trust anchor = embedded key

The minisign public key is **hardcoded in `install.sh` itself** (`MINISIGN_PUBKEY`
= the base64 body of `override_release_minisign.pub`, key id `BF7A2618AF8CEAE9`).
Verification always uses that embedded key, **never** a key downloaded at install
time — so an attacker who compromised the GitHub release still could not forge an
accepted binary without also rewriting the key across every historical commit.
The release-published `.pub` file is redundancy, not something trusted over the
embedded copy. A bad or missing signature aborts the install (**fail-closed**).

### Verifier

When the audited [`minisign`](https://jedisct1.github.io/minisign/) tool is
installed, the script uses it directly
(`minisign -V -P <key> -m <file> -x <sig>`, which also checks the trusted-comment
global signature).

### No-minisign prompt

When `minisign` is **absent**, the script never silently improvises — it asks
(on `/dev/tty`, so it works under `curl … | bash`) how to proceed:

1. **use the built-in OpenSSL verifier** — a re-implementation of minisign
   verification, handy when you can't install minisign;
2. **abort** to install minisign and re-run (default / recommended); or
3. **skip** verification, which requires typing the exact phrase
   `I understand the security concerns`.

The `/dev/tty` check *opens* the device rather than testing mode bits (which are
set even with no controlling terminal). With **no terminal available** (CI, cron,
`curl … | bash` with no tty) it fails closed → `noninteractive` → abort.

### OpenSSL fallback details

If the user picks option 1: minisign signatures are the **prehashed `ED`**
variant = Ed25519 over BLAKE2b-512 of the file. The script computes
`openssl dgst -blake2b512 -binary`, slices the 2-byte algo / 8-byte key-id /
64-byte signature, wraps the 32-byte raw key in a fixed Ed25519 SPKI DER header,
and runs `openssl pkeyutl -verify -rawin`. Requires OpenSSL 1.1.1+ with BLAKE2b
(capability-probed; missing support aborts).

### Fail-closed summary

A bad/missing signature, a key-id mismatch, an unavailable verifier, or no tty to
ask all **abort**. Only `--insecure-skip-verify` bypasses verification, and only
when passed explicitly up front.
