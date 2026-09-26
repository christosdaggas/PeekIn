#!/bin/bash
# Build the peekin RPMs as a normal user (no root needed):
#   packaging/build-rpm.sh
# Results: dist/rpm/peekin-*.rpm (the source RPM stays in target/rpmbuild/SRPMS/).
# The source tarball vendors all crates, so the RPM itself builds offline
# (also in mock: mock -r fedora-44-x86_64 target/rpmbuild/SRPMS/*.src.rpm).
#   RPMBUILD_NODEPS=1  skip the BuildRequires check (headers provided otherwise)
#   SRPM_ONLY=1        stop after the source RPM
set -euo pipefail

RUST_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$RUST_DIR/packaging/peekin.spec"
NAME=peekin
VERSION="$(sed -n 's/^Version:[[:space:]]*//p' "$SPEC")"
TOP="$RUST_DIR/target/rpmbuild"
DIST="$RUST_DIR/dist/rpm"
STAGE="$TOP/stage/$NAME-$VERSION"

die() { echo "error: $*" >&2; exit 1; }

# Fail early with the command that fixes each missing prerequisite instead of
# half-way through rpmbuild.
command -v rpmbuild >/dev/null || die "rpmbuild is missing: sudo dnf install rpm-build 'dnf-command(builddep)'"
command -v cargo >/dev/null || die "cargo is missing: sudo dnf install cargo rust"
command -v curl >/dev/null || die "curl is missing: sudo dnf install curl"
crate_version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$RUST_DIR/Cargo.toml" | head -n1)"
[ "$crate_version" = "$VERSION" ] || die "spec Version $VERSION differs from crate version $crate_version"
if [ "${RPMBUILD_NODEPS:-0}" != 1 ] && [ "${SRPM_ONLY:-0}" != 1 ]; then
    # Names only: rpm -q --whatprovides takes no version ranges; rpmbuild
    # itself enforces the versions (e.g. rust >= 1.92) below.
    if missing="$(rpmspec -q --buildrequires "$SPEC" 2>/dev/null | while read -r dep _; do
        rpm -q --whatprovides "$dep" >/dev/null 2>&1 || printf ' %s' "$dep"
    done)" && [ -n "$missing" ]; then
        die "missing build dependencies:$missing
       install them with: sudo dnf builddep $SPEC"
    fi
fi

rm -rf "$TOP/stage"
mkdir -p "$STAGE/rust" "$TOP/SOURCES"

echo ">>> Packing sources"
tar -C "$RUST_DIR" --exclude=./.git --exclude=./target --exclude=./dist --exclude=./.unlazy --exclude='*.bundle' -cf - . | tar -C "$STAGE/rust" -xf -

echo ">>> Vendoring crates"
mkdir -p "$STAGE/rust/.cargo"
(cd "$STAGE/rust" && cargo vendor --locked --quiet vendor)
cat > "$STAGE/rust/.cargo/config.toml" <<'EOF_CONFIG'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF_CONFIG
tar -C "$TOP/stage" -czf "$TOP/SOURCES/$NAME-$VERSION.tar.gz" "$NAME-$VERSION"
rm -rf "$TOP/stage"
install -m644 "$RUST_DIR/data/peekin.sysusers" "$TOP/SOURCES/peekin.sysusers"

echo ">>> Fetching face models"
"$RUST_DIR/data/fetch-models.sh" "$TOP/SOURCES"

echo ">>> Building RPMs"
if [ "${SRPM_ONLY:-0}" = 1 ]; then
    rpmbuild --define "_topdir $TOP" -bs "$SPEC"
elif [ "${RPMBUILD_NODEPS:-0}" = 1 ]; then
    # For a local build with development headers provided through explicit
    # OpenCV environment overrides; the spec still declares BuildRequires.
    rpmbuild --nodeps --define "_topdir $TOP" -ba "$SPEC"
else
    rpmbuild --define "_topdir $TOP" -ba "$SPEC"
fi

[ "${SRPM_ONLY:-0}" = 1 ] && { echo ">>> Done: $TOP/SRPMS"; exit 0; }
# Export this release's main and debug packages for CI checks and artifacts.
# The install command below selects only the main package, not debug packages.
RELEASE="$(sed -n 's/^Release:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$SPEC")"
mkdir -p "$DIST"
rm -f "$DIST"/$NAME-*.rpm
find "$TOP/RPMS" \( -name "$NAME-$VERSION-$RELEASE.*.rpm" \
    -o -name "$NAME-debuginfo-$VERSION-$RELEASE.*.rpm" \
    -o -name "$NAME-debugsource-$VERSION-$RELEASE.*.rpm" \) -exec cp -p {} "$DIST"/ \;

echo
echo ">>> Done:"
find "$DIST" -name '*.rpm' -printf '    %p\n'
echo "Install or upgrade with: sudo dnf install $DIST/$NAME-$VERSION-*.rpm"
