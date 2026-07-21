#!/usr/bin/env bash
#
# build-deb.sh — build a .deb package for the `override` secure file-destruction
# tool. Compiles the release binary with cargo, assembles a policy-compliant
# Debian package tree, and produces override-tool_<version>_<arch>.deb.
#
# Usage:
#   packaging/build-deb.sh [--outdir DIR]
#
# Requires: cargo, dpkg-deb, dpkg-architecture (dpkg-dev). Run from anywhere;
# paths are resolved relative to the repository root.

set -euo pipefail

# ---- locations -------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUTDIR="$REPO_ROOT/dist"
while [ $# -gt 0 ]; do
    case "$1" in
        --outdir) OUTDIR="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# ---- metadata --------------------------------------------------------------

PKG="override-tool"
BIN_NAME="override"
VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -1)"
DEB_REVISION="1"
MAINTAINER="RaphtaliaShoko <raphael.canevet@pm.me>"

if command -v dpkg-architecture >/dev/null 2>&1; then
    ARCH="$(dpkg-architecture -qDEB_HOST_ARCH)"
else
    ARCH="$(dpkg --print-architecture)"
fi

echo ">> Building $PKG $VERSION for $ARCH"

# ---- compile ---------------------------------------------------------------

echo ">> cargo build --release"
( cd "$REPO_ROOT" && cargo build --release )
BIN="$REPO_ROOT/target/release/$BIN_NAME"
[ -x "$BIN" ] || { echo "release binary not found at $BIN" >&2; exit 1; }

# ---- assemble package tree -------------------------------------------------

BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
ROOT="$BUILD/$PKG"

install -d "$ROOT/DEBIAN"
install -d "$ROOT/usr/bin"
install -d "$ROOT/usr/share/man/man1"
install -d "$ROOT/usr/share/doc/$PKG"
install -d "$ROOT/usr/share/bash-completion/completions"

# Binary (stripped already via release profile).
install -m 0755 "$BIN" "$ROOT/usr/bin/$BIN_NAME"

# Man page (gzip -9n for reproducibility).
gzip -9nc "$SCRIPT_DIR/override.1" > "$ROOT/usr/share/man/man1/$BIN_NAME.1.gz"

# Bash completion.
install -m 0644 "$SCRIPT_DIR/override.bash-completion" \
    "$ROOT/usr/share/bash-completion/completions/$BIN_NAME"

# Copyright.
install -m 0644 "$SCRIPT_DIR/copyright" "$ROOT/usr/share/doc/$PKG/copyright"

# Debian changelog.
gzip -9nc "$SCRIPT_DIR/changelog" > "$ROOT/usr/share/doc/$PKG/changelog.Debian.gz"

# Reference documentation and README.
install -m 0644 "$REPO_ROOT/README.md" "$ROOT/usr/share/doc/$PKG/README.md"
for f in "$REPO_ROOT"/docs/*.md; do
    gzip -9nc "$f" > "$ROOT/usr/share/doc/$PKG/$(basename "$f").gz"
done

# ---- control metadata ------------------------------------------------------

# Installed-Size in KiB (Debian policy: du of the tree, excluding DEBIAN).
INSTALLED_SIZE="$(du -k -s --exclude=DEBIAN "$ROOT" | cut -f1)"

# Runtime library dependencies. Prefer dpkg-shlibdeps for accuracy; fall back to
# a conservative manual set matching the binary's glibc/libgcc requirements.
DEPENDS="libc6 (>= 2.34), libgcc-s1 (>= 3.0)"
if command -v dpkg-shlibdeps >/dev/null 2>&1; then
    SHLIB_TMP="$(mktemp -d)"
    mkdir -p "$SHLIB_TMP/debian"
    : > "$SHLIB_TMP/debian/control"
    if ( cd "$SHLIB_TMP" && dpkg-shlibdeps -O "$ROOT/usr/bin/$BIN_NAME" ) \
            > "$SHLIB_TMP/out" 2>/dev/null; then
        DETECTED="$(sed -n 's/^shlibs:Depends=//p' "$SHLIB_TMP/out")"
        [ -n "$DETECTED" ] && DEPENDS="$DETECTED"
    fi
    rm -rf "$SHLIB_TMP"
fi

cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: ${VERSION}-${DEB_REVISION}
Architecture: $ARCH
Maintainer: $MAINTAINER
Installed-Size: $INSTALLED_SIZE
Depends: $DEPENDS
Section: utils
Priority: optional
Homepage: https://github.com/RaphtaliaShoko/override
Description: Secure file-destruction tool (shred-like) with crypto-shredding
 override securely destroys files so their content cannot be recovered. Its
 default pipeline crypto-shreds each target (encrypt in place, discard the key),
 then applies random and zero overwrite passes, renames, and unlinks the file,
 flushing and fsync'ing every write.
 .
 It also supports multi-pass and custom pipelines, free-space wiping, an
 emergency "no-stop" mode, and self-resilience features. Note that on SSDs and
 copy-on-write filesystems, no in-place method -- neither the overwrites nor the
 crypto-shred -- is guaranteed to reach the original physical blocks; there,
 prefer full-disk encryption, ATA/NVMe secure-erase, or physical destruction.
EOF

# Normalize permissions on generated files (gzip redirects honor the umask,
# which can yield group-writable modes that lintian flags).
find "$ROOT/usr/share" -type f -exec chmod 0644 {} +
find "$ROOT/usr" -type d -exec chmod 0755 {} +

# conffiles: none (no files under /etc).

# ---- build the .deb --------------------------------------------------------

mkdir -p "$OUTDIR"
DEB="$OUTDIR/${PKG}_${VERSION}-${DEB_REVISION}_${ARCH}.deb"

# Root-owned files inside the archive without needing to be root.
if dpkg-deb --help 2>&1 | grep -q -- '--root-owner-group'; then
    dpkg-deb --root-owner-group --build "$ROOT" "$DEB" >/dev/null
else
    fakeroot dpkg-deb --build "$ROOT" "$DEB" >/dev/null
fi

echo ">> Built $DEB"
dpkg-deb --info "$DEB" | sed 's/^/   /'
echo ">> Contents:"
dpkg-deb --contents "$DEB" | sed 's/^/   /'
