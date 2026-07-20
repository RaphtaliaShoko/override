#!/usr/bin/env bash
#
# install.sh — install, update, or remove the `override` secure file-destruction
# tool system-wide, using the prebuilt release binaries published on GitHub.
#
# The binary for the host architecture is downloaded from:
#   https://github.com/RaphtaliaShoko/override/releases/download/<VERSION>/override-<ARCH>-linux
#
# Its integrity is then verified against BOTH the SHA256 and SHA512 digests
# published in the release's "checksums" asset before it is installed.
#
# Supported architectures: x86_64, aarch64 (Linux only).
#
# Usage:
#   ./install.sh [--version <vX.Y.Z>] [--prefix <dir>] [--dry] [--no-checksum]
#   ./install.sh --remove [--prefix <dir>] [--dry]
#   ./install.sh --help
#
# Behaviour:
#   * Default action installs (or, if already present, updates) override to the
#     requested version — running it again is how you upgrade/downgrade.
#   * The download is verified against the published SHA256 AND SHA512 checksums;
#     a mismatch (or a missing checksums asset) aborts the install.
#   * --no-checksum skips that verification (e.g. for older releases published
#     without a checksums file) — not recommended.
#   * --remove uninstalls it.
#   * --dry prints exactly what would happen (and checks the download URL and the
#     checksums asset are reachable) without touching the system.
#
# The default install prefix is /usr/local/bin; sudo is used automatically only
# when the target directory is not writable by the current user.

set -euo pipefail

# ---- configuration ---------------------------------------------------------

REPO="RaphtaliaShoko/override"
BIN_NAME="override"
CHECKSUMS_NAME="checksums"
DEFAULT_VERSION="v1.0.0"
DEFAULT_PREFIX="/usr/local/bin"

VERSION="$DEFAULT_VERSION"
INSTALL_DIR="$DEFAULT_PREFIX"
ACTION="install"
DRY=0
VERIFY_CHECKSUM=1
SUDO=""

# ---- logging ---------------------------------------------------------------

if [ -t 1 ]; then
    C_INFO='\033[1;34m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'
    C_ERR='\033[1;31m'; C_OFF='\033[0m'
else
    C_INFO=''; C_OK=''; C_WARN=''; C_ERR=''; C_OFF=''
fi

info() { printf "${C_INFO}==>${C_OFF} %s\n" "$*"; }
ok()   { printf "${C_OK}==>${C_OFF} %s\n" "$*"; }
warn() { printf "${C_WARN}warning:${C_OFF} %s\n" "$*" >&2; }
err()  { printf "${C_ERR}error:${C_OFF} %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() {
    # Print the contiguous header comment block (from line 3 until the first
    # non-comment line), stripping the leading "# ".
    awk 'NR>=3 { if ($0 ~ /^#/) { sub(/^# ?/, ""); print } else exit }' "$0"
}

# ---- helpers ---------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

detect_arch() {
    local m
    m="$(uname -m)"
    case "$m" in
        x86_64 | amd64)  echo "x86_64" ;;
        aarch64 | arm64) echo "aarch64" ;;
        *) die "unsupported architecture: '$m' (only x86_64 and aarch64 are published)" ;;
    esac
}

# Decide whether privileged writes are needed for $INSTALL_DIR, and whether we
# can escalate. Sets the global $SUDO to "" or "sudo".
resolve_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
        return
    fi
    # Walk up to the nearest existing ancestor and test its writability, so a
    # nested target like /opt/foo/bin (created later by mkdir -p) is judged by
    # whichever parent already exists.
    local d="$INSTALL_DIR"
    while [ ! -e "$d" ]; do
        d="$(dirname "$d")"
    done
    if [ -w "$d" ]; then
        SUDO=""
    elif have sudo; then
        SUDO="sudo"
    else
        die "$INSTALL_DIR is not writable and 'sudo' is not available; re-run as root or pass --prefix <writable dir>"
    fi
}

# HEAD-check a URL (used by --dry). Returns 0 if reachable.
url_reachable() {
    local url="$1"
    if have curl; then
        curl -fsIL --proto '=https' --tlsv1.2 -o /dev/null "$url"
    elif have wget; then
        wget -q --spider "$url"
    else
        return 2
    fi
}

# Download $1 to $2.
download() {
    local url="$1" dest="$2"
    if have curl; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$dest" "$url"
    elif have wget; then
        wget -O "$dest" "$url"
    else
        die "need either 'curl' or 'wget' to download the binary"
    fi
}

asset_url() {
    printf 'https://github.com/%s/releases/download/%s/%s-%s-linux\n' \
        "$REPO" "$VERSION" "$BIN_NAME" "$1"
}

checksums_url() {
    printf 'https://github.com/%s/releases/download/%s/%s\n' \
        "$REPO" "$VERSION" "$CHECKSUMS_NAME"
}

# Print the lowercase hex digest of a file. $1 = bits (256|512), $2 = file.
# Tries sha256sum/sha512sum, then shasum -a, then openssl dgst. Returns non-zero
# if no tool is available.
sha_of() {
    local bits="$1" file="$2"
    if have "sha${bits}sum"; then
        "sha${bits}sum" "$file" | awk '{print $1}'
    elif have shasum; then
        shasum -a "$bits" "$file" | awk '{print $1}'
    elif have openssl; then
        openssl dgst "-sha${bits}" "$file" | awk '{print $NF}'
    else
        return 3
    fi
}

# Verify $1 (a downloaded binary) against the published SHA256 and SHA512 digests
# for architecture $2. Aborts on any mismatch, a missing entry, or an
# unreachable/absent checksums asset (fail closed).
#
# The published "checksums" asset holds both digests in coreutils format
# (`<hash>  <filename>`); SHA256 lines have a 64-char hex hash and SHA512 lines a
# 128-char one, so we select each by hash length and asset filename.
verify_checksums() {
    local file="$1" arch="$2"
    local asset url tmpc exp256 exp512 act256 act512
    asset="$BIN_NAME-$arch-linux"
    url="$(checksums_url)"

    info "verifying checksums (SHA256 + SHA512)…"
    tmpc="$(mktemp)"
    if ! download "$url" "$tmpc"; then
        rm -f "$tmpc"
        die "could not download the checksums asset from $url
Pass --no-checksum to skip verification (e.g. for a release published without one)."
    fi

    exp256="$(awk -v f="$asset" 'length($1)==64  && $2==f {print $1; exit}' "$tmpc")"
    exp512="$(awk -v f="$asset" 'length($1)==128 && $2==f {print $1; exit}' "$tmpc")"
    rm -f "$tmpc"

    [ -n "$exp256" ] || die "no SHA256 entry for '$asset' in the checksums asset"
    [ -n "$exp512" ] || die "no SHA512 entry for '$asset' in the checksums asset"

    act256="$(sha_of 256 "$file")" \
        || die "cannot compute SHA256 (need sha256sum, shasum, or openssl)"
    act512="$(sha_of 512 "$file")" \
        || die "cannot compute SHA512 (need sha512sum, shasum, or openssl)"

    if [ "$act256" != "$exp256" ]; then
        die "SHA256 mismatch for $asset — download may be corrupt or tampered with; aborting.
  expected: $exp256
  actual:   $act256"
    fi
    if [ "$act512" != "$exp512" ]; then
        die "SHA512 mismatch for $asset — download may be corrupt or tampered with; aborting.
  expected: $exp512
  actual:   $act512"
    fi

    ok "checksums verified (SHA256 + SHA512)"
}

# ---- actions ---------------------------------------------------------------

do_install() {
    local arch url dest tmp current
    arch="$(detect_arch)"
    url="$(asset_url "$arch")"
    dest="$INSTALL_DIR/$BIN_NAME"
    resolve_sudo

    if [ -x "$dest" ]; then
        current="$("$dest" --version 2>/dev/null || echo "unknown")"
        info "override is already installed ($current) — updating to $VERSION"
    else
        info "installing override $VERSION"
    fi
    info "architecture : $arch"
    info "source       : $url"
    info "destination  : $dest${SUDO:+  (via sudo)}"

    if [ "$VERIFY_CHECKSUM" -eq 1 ]; then
        info "checksums    : $(checksums_url)"
    else
        warn "checksum verification disabled (--no-checksum)"
    fi

    if [ "$DRY" -eq 1 ]; then
        if url_reachable "$url"; then
            ok "[dry] release asset is reachable"
        else
            warn "[dry] release asset is NOT reachable — check the --version tag"
        fi
        if [ "$VERIFY_CHECKSUM" -eq 1 ]; then
            if url_reachable "$(checksums_url)"; then
                ok "[dry] checksums asset is reachable"
            else
                warn "[dry] checksums asset is NOT reachable — install would abort (or use --no-checksum)"
            fi
        fi
        if [ "$VERIFY_CHECKSUM" -eq 1 ]; then
            info "[dry] would download, verify checksums, and install to $dest; no changes made"
        else
            info "[dry] would download and install to $dest (checksum verification skipped); no changes made"
        fi
        return 0
    fi

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    info "downloading…"
    download "$url" "$tmp/$BIN_NAME"

    # Verify integrity against the published SHA256 + SHA512 digests before the
    # binary is ever made executable or installed.
    if [ "$VERIFY_CHECKSUM" -eq 1 ]; then
        verify_checksums "$tmp/$BIN_NAME" "$arch"
    fi

    # Basic sanity: make sure we got an ELF binary, not an HTML error page.
    if ! head -c 4 "$tmp/$BIN_NAME" | grep -q $'\x7fELF'; then
        die "downloaded file is not an ELF binary (bad version tag or network error?)"
    fi

    chmod +x "$tmp/$BIN_NAME"
    $SUDO mkdir -p "$INSTALL_DIR"
    $SUDO install -m 0755 "$tmp/$BIN_NAME" "$dest"

    ok "installed $("$dest" --version 2>/dev/null || echo "$BIN_NAME") -> $dest"
    if ! printf '%s' ":$PATH:" | grep -q ":$INSTALL_DIR:"; then
        warn "$INSTALL_DIR is not on your \$PATH; add it to use '$BIN_NAME' directly"
    fi
}

do_remove() {
    local dest="$INSTALL_DIR/$BIN_NAME"
    resolve_sudo

    if [ ! -e "$dest" ]; then
        info "override is not installed at $dest — nothing to remove"
        return 0
    fi

    info "removing $dest${SUDO:+  (via sudo)}"
    if [ "$DRY" -eq 1 ]; then
        info "[dry] would remove $dest; no changes made"
        return 0
    fi

    $SUDO rm -f "$dest"
    ok "override removed"
}

# ---- argument parsing ------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --version)       VERSION="${2:?--version needs a value}"; shift 2 ;;
        --version=*)     VERSION="${1#*=}"; shift ;;
        --prefix)        INSTALL_DIR="${2:?--prefix needs a value}"; shift 2 ;;
        --prefix=*)      INSTALL_DIR="${1#*=}"; shift ;;
        --remove | --uninstall) ACTION="remove"; shift ;;
        --dry | --dry-run)      DRY=1; shift ;;
        --no-checksum | --skip-checksum) VERIFY_CHECKSUM=0; shift ;;
        -h | --help)     usage; exit 0 ;;
        *) err "unknown option: $1"; echo; usage; exit 2 ;;
    esac
done

# Normalise the version to a leading 'v' (accept both "1.0.0" and "v1.0.0").
case "$VERSION" in
    v*) ;;
    *)  VERSION="v$VERSION" ;;
esac

[ "$(uname -s)" = "Linux" ] || die "only Linux is supported (got $(uname -s))"

case "$ACTION" in
    install) do_install ;;
    remove)  do_remove ;;
esac
