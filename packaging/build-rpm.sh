#!/usr/bin/env bash
#
# build-rpm.sh — build an .rpm package for the `override` secure file-destruction
# tool. Produces a source tarball from the git tree and runs rpmbuild against
# packaging/override-tool.spec.
#
# Must run on an RPM-based host (Fedora/RHEL/openSUSE) with rpmbuild, cargo, and
# rust available. On Debian-based dev machines, run it inside a Fedora VM/container
# instead (the produced .rpm is copied back into dist/ by the caller).
#
# Usage:
#   packaging/build-rpm.sh [--outdir DIR]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUTDIR="$REPO_ROOT/dist"
while [ $# -gt 0 ]; do
    case "$1" in
        --outdir) OUTDIR="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v rpmbuild >/dev/null 2>&1 || {
    echo "rpmbuild not found — run this on an RPM-based host (e.g. the Fedora VM)." >&2
    exit 1
}

PKG="override-tool"
SPEC="$SCRIPT_DIR/$PKG.spec"
VERSION="$(sed -n 's/^Version:[[:space:]]*//p' "$SPEC" | head -1)"

echo ">> Building $PKG $VERSION"

# rpmbuild tree.
TOPDIR="$(mktemp -d)"
trap 'rm -rf "$TOPDIR"' EXIT
mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Source tarball straight from the committed tree (excludes target/, VM/, dist/
# via .gitignore, since git archive only ships tracked files).
echo ">> Creating source tarball"
( cd "$REPO_ROOT" && git archive --format=tar.gz \
    --prefix="$PKG-$VERSION/" -o "$TOPDIR/SOURCES/$PKG-$VERSION.tar.gz" HEAD )

cp "$SPEC" "$TOPDIR/SPECS/"

echo ">> rpmbuild -bb"
rpmbuild --define "_topdir $TOPDIR" -bb "$TOPDIR/SPECS/$(basename "$SPEC")"

mkdir -p "$OUTDIR"
find "$TOPDIR/RPMS" -name '*.rpm' -exec cp -v {} "$OUTDIR/" \;

echo ">> Done. Artifacts in $OUTDIR:"
ls -1 "$OUTDIR"/*.rpm
