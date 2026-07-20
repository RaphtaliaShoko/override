#!/usr/bin/env bash
#
# install.sh — install, update, or remove the `override` secure file-destruction
# tool system-wide, using the prebuilt release binaries published on GitHub.
#
# The binary for the host architecture is downloaded from:
#   https://github.com/RaphtaliaShoko/override/releases/download/<VERSION>/override-<ARCH>-linux
#
# Its authenticity is then verified against the project's minisign signature
# (override-<ARCH>-linux.minisig) using the public key EMBEDDED in this script
# before it is installed.
#
# Trust model:
#   The minisign public key is hardcoded below (MINISIGN_PUBKEY). That embedded
#   key — carried in this script's git history across many old commits — is the
#   trust anchor. Verification always uses it, never a key downloaded at install
#   time, so an attacker who compromises the GitHub release cannot swap in a
#   fake key: they would also have to rewrite this key in every historical
#   commit. The same key is published in the release (override_release_minisign.pub)
#   only for convenience/redundancy; it is NOT trusted over the embedded copy.
#
# Supported architectures: x86_64, aarch64 (Linux only).
#
# Usage:
#   ./install.sh [--version <vX.Y.Z>] [--prefix <dir>] [--dry] [--insecure-skip-verify]
#   ./install.sh --remove [--prefix <dir>] [--dry]
#   ./install.sh --help
#
# Behaviour:
#   * Default action installs (or, if already present, updates) override to the
#     requested version — running it again is how you upgrade/downgrade.
#   * The download is verified against the published minisign signature using the
#     embedded public key; a bad or missing signature aborts the install.
#   * Verification prefers the `minisign` tool. If it is NOT installed, the script
#     asks (on the terminal) how to proceed: [1] use the built-in OpenSSL
#     (Ed25519 + BLAKE2b) verifier, [2] abort so you can install minisign and
#     re-run, or [3] skip verification after an explicit acknowledgement. With no
#     terminal available (CI/cron) it fails closed and aborts.
#   * --insecure-skip-verify skips signature verification entirely (no prompt) —
#     strongly discouraged; only for offline/debugging use at your own risk.
#   * --remove uninstalls it.
#   * --dry prints exactly what would happen (and checks the download URL and the
#     signature asset are reachable) without touching the system.
#
# The default install prefix is /usr/local/bin; sudo is used automatically only
# when the target directory is not writable by the current user.

set -euo pipefail

# ---- configuration ---------------------------------------------------------

REPO="RaphtaliaShoko/override"
BIN_NAME="override"
DEFAULT_VERSION="v1.0.0"
DEFAULT_PREFIX="/usr/local/bin"

# Trust anchor: the project's minisign public key, embedded here on purpose.
# This is the base64 body of override_release_minisign.pub (key id below).
# Changing these two lines changes who this script trusts — do not edit them
# unless you are deliberately rotating the signing key.
MINISIGN_PUBKEY="RWTp6oyvGCZ6v4WoRoFH8TpsUbOL5gLgq4/bAiD9VizELBu4GNSoPhao"
MINISIGN_PUBKEY_ID="BF7A2618AF8CEAE9"

VERSION="$DEFAULT_VERSION"
INSTALL_DIR="$DEFAULT_PREFIX"
ACTION="install"
DRY=0
VERIFY_SIG=1
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

sig_url() {
    printf 'https://github.com/%s/releases/download/%s/%s-%s-linux.minisig\n' \
        "$REPO" "$VERSION" "$BIN_NAME" "$1"
}

# Pure-OpenSSL fallback verifier for minisign's prehashed ('ED') signatures:
# Ed25519 over BLAKE2b-512 of the file. Used only when `minisign` is absent.
#   $1 = file, $2 = .minisig path, $3 = base64 public key (full .pub body)
# Returns: 0 verified, 1 verification failed / malformed, 10 openssl unusable.
verify_sig_openssl() {
    local file="$1" sigfile="$2" pub_b64="$3" wd rc
    have openssl || return 10
    # Needs OpenSSL 1.1.1+ (Ed25519 raw verify) and a BLAKE2b-512 digest.
    openssl pkeyutl -help 2>&1 | grep -q -- '-rawin' || return 10
    openssl dgst -blake2b512 -binary /dev/null >/dev/null 2>&1 || return 10

    wd="$(mktemp -d)"

    # --- decode the public key: 2-byte algo 'Ed' + 8-byte key id + 32-byte key
    printf '%s' "$pub_b64" | base64 -d > "$wd/pub.raw" 2>/dev/null || { rm -rf "$wd"; return 1; }
    [ "$(wc -c < "$wd/pub.raw")" -eq 42 ] || { rm -rf "$wd"; return 1; }
    [ "$(dd if="$wd/pub.raw" bs=1 count=2 2>/dev/null)" = "Ed" ] || { rm -rf "$wd"; return 1; }
    dd if="$wd/pub.raw" bs=1 skip=2  count=8  of="$wd/pkid" 2>/dev/null
    dd if="$wd/pub.raw" bs=1 skip=10 count=32 of="$wd/pk32" 2>/dev/null

    # --- decode the signature line (2nd line): algo 'ED' + 8-byte key id + 64-byte sig
    sed -n 2p "$sigfile" | base64 -d > "$wd/sig.raw" 2>/dev/null || { rm -rf "$wd"; return 1; }
    [ "$(wc -c < "$wd/sig.raw")" -eq 74 ] || { rm -rf "$wd"; return 1; }
    # Only the prehashed variant is handled here; anything else is unverifiable
    # by this fallback (real releases use 'ED').
    [ "$(dd if="$wd/sig.raw" bs=1 count=2 2>/dev/null)" = "ED" ] || { rm -rf "$wd"; return 10; }
    dd if="$wd/sig.raw" bs=1 skip=2  count=8  of="$wd/skid"  2>/dev/null
    dd if="$wd/sig.raw" bs=1 skip=10 count=64 of="$wd/sig64" 2>/dev/null

    # key id in the signature must match the key id of our embedded key
    cmp -s "$wd/pkid" "$wd/skid" || { rm -rf "$wd"; return 1; }

    # wrap the 32-byte raw key in a fixed Ed25519 SubjectPublicKeyInfo DER header
    printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > "$wd/spki.der"
    cat "$wd/pk32" >> "$wd/spki.der"

    # message signed by minisign's prehashed scheme = BLAKE2b-512(file)
    openssl dgst -blake2b512 -binary "$file" > "$wd/hash" 2>/dev/null || { rm -rf "$wd"; return 10; }
    [ "$(wc -c < "$wd/hash")" -eq 64 ] || { rm -rf "$wd"; return 10; }

    local out
    out="$(openssl pkeyutl -verify -pubin -inkey "$wd/spki.der" -rawin \
              -in "$wd/hash" -sigfile "$wd/sig64" 2>&1)"; rc=$?
    rm -rf "$wd"
    { [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -qi 'Signature Verified Successfully'; }
}

# Print how to install minisign on common platforms (to stderr).
minisign_install_hint() {
    err "install minisign, then re-run this installer:"
    err "  Debian/Ubuntu : sudo apt install minisign"
    err "  Fedora        : sudo dnf install minisign"
    err "  Arch          : sudo pacman -S minisign"
    err "  Alpine        : sudo apk add minisign"
    err "  macOS (brew)  : brew install minisign"
    err "  Rust (cargo)  : cargo install rsign2   # 'rsign', minisign-compatible"
}

# When minisign is not installed, ask the user how to proceed. Prompts on the
# controlling terminal (/dev/tty), so it still works under `curl … | bash`.
# Sets the global $DECISION to: openssl | install | skip | noninteractive.
DECISION=""
prompt_no_minisign() {
    DECISION=""

    # No controlling terminal (CI, cron, piped without a tty) → cannot ask.
    # NB: `[ -r /dev/tty ]` only checks the device-node mode bits, which are set
    # even with no controlling terminal, so we must actually try to open it.
    if ! { ( exec </dev/tty ) 2>/dev/null && ( exec >/dev/tty ) 2>/dev/null; }; then
        DECISION="noninteractive"
        return
    fi

    {
        printf '\n'
        printf 'minisign is not installed, so the download cannot be verified with the\n'
        printf 'canonical, audited tool. How would you like to proceed?\n\n'
        printf '  [1] Use the built-in OpenSSL verifier (an Ed25519 + BLAKE2b\n'
        printf '      re-implementation of minisign verification in this script)\n'
        printf '  [2] Abort — install minisign yourself, then re-run this installer  (recommended)\n'
        printf '  [3] Skip verification entirely (NOT recommended)\n\n'
    } > /dev/tty

    local ans ack
    while :; do
        printf 'Enter choice [1/2/3] (default 2): ' > /dev/tty
        IFS= read -r ans < /dev/tty || ans=""
        case "${ans:-2}" in
            1) DECISION="openssl"; return ;;
            2) DECISION="install"; return ;;
            3)
                printf 'Type "I understand the security concerns" to skip verification: ' > /dev/tty
                IFS= read -r ack < /dev/tty || ack=""
                ack="$(printf '%s' "$ack" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
                if [ "$ack" = "i understand the security concerns" ]; then
                    DECISION="skip"; return
                fi
                printf 'Acknowledgement did not match; verification will NOT be skipped.\n\n' > /dev/tty
                ;;
            *) printf 'Please enter 1, 2, or 3.\n' > /dev/tty ;;
        esac
    done
}

# Verify $1 (a downloaded binary) for architecture $2 against the project's
# minisign signature, using the EMBEDDED public key (never a downloaded one).
# Aborts on a bad/missing signature or if no verifier is available (fail closed).
verify_signature() {
    local file="$1" arch="$2"
    local asset url tmpsig
    asset="$BIN_NAME-$arch-linux"
    url="$(sig_url "$arch")"

    info "verifying signature (minisign key $MINISIGN_PUBKEY_ID)…"
    tmpsig="$(mktemp)"
    if ! download "$url" "$tmpsig"; then
        rm -f "$tmpsig"
        die "could not download the signature from $url
Pass --insecure-skip-verify to skip verification (NOT recommended)."
    fi

    # Preferred path: the canonical, audited minisign tool (also verifies the
    # signed trusted comment via minisign's global signature).
    if have minisign; then
        if minisign -V -P "$MINISIGN_PUBKEY" -m "$file" -x "$tmpsig" >/dev/null 2>&1; then
            rm -f "$tmpsig"
            ok "signature verified (minisign, key $MINISIGN_PUBKEY_ID)"
            return 0
        fi
        rm -f "$tmpsig"
        die "signature verification FAILED for $asset — download may be corrupt or tampered with; aborting.
The binary does not match the project's signing key ($MINISIGN_PUBKEY_ID)."
    fi

    # minisign is not installed — let the user decide (never silently fall back).
    prompt_no_minisign
    case "$DECISION" in
        openssl) : ;;                # fall through to the OpenSSL verifier below
        install)
            rm -f "$tmpsig"
            err "aborting: minisign is not installed."
            minisign_install_hint
            die "then re-run this installer (or pass --insecure-skip-verify to skip — NOT recommended)."
            ;;
        skip)
            rm -f "$tmpsig"
            warn "proceeding WITHOUT signature verification at your request"
            return 0
            ;;
        noninteractive|*)
            rm -f "$tmpsig"
            err "minisign is not installed and there is no terminal to ask how to proceed."
            minisign_install_hint
            die "or re-run with --insecure-skip-verify to skip verification (NOT recommended)."
            ;;
    esac

    # Fallback: pure-OpenSSL Ed25519 + BLAKE2b verification (user-selected).
    verify_sig_openssl "$file" "$tmpsig" "$MINISIGN_PUBKEY"
    local rc=$?
    rm -f "$tmpsig"
    case "$rc" in
        0)  ok "signature verified (openssl Ed25519, key $MINISIGN_PUBKEY_ID)"; return 0 ;;
        10) die "the built-in OpenSSL verifier is unavailable (need OpenSSL 1.1.1+ with BLAKE2b).
Install 'minisign' and re-run, or pass --insecure-skip-verify to skip verification (NOT recommended)." ;;
        *)  die "signature verification FAILED for $asset — download may be corrupt or tampered with; aborting.
The binary does not match the project's signing key ($MINISIGN_PUBKEY_ID)." ;;
    esac
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

    if [ "$VERIFY_SIG" -eq 1 ]; then
        info "signature    : $(sig_url "$arch")"
    else
        warn "signature verification disabled (--insecure-skip-verify)"
    fi

    if [ "$DRY" -eq 1 ]; then
        if url_reachable "$url"; then
            ok "[dry] release asset is reachable"
        else
            warn "[dry] release asset is NOT reachable — check the --version tag"
        fi
        if [ "$VERIFY_SIG" -eq 1 ]; then
            if url_reachable "$(sig_url "$arch")"; then
                ok "[dry] signature asset is reachable"
            else
                warn "[dry] signature asset is NOT reachable — install would abort (or use --insecure-skip-verify)"
            fi
            info "[dry] would download, verify the signature, and install to $dest; no changes made"
        else
            info "[dry] would download and install to $dest (signature verification skipped); no changes made"
        fi
        return 0
    fi

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    info "downloading…"
    download "$url" "$tmp/$BIN_NAME"

    # Verify authenticity against the embedded signing key before the binary is
    # ever made executable or installed.
    if [ "$VERIFY_SIG" -eq 1 ]; then
        verify_signature "$tmp/$BIN_NAME" "$arch"
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
        # Skip signature verification (discouraged). Old checksum-era flag names
        # are accepted as aliases for backward compatibility.
        --insecure-skip-verify | --no-verify | --skip-verify | --no-checksum | --skip-checksum)
            VERIFY_SIG=0; shift ;;
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
