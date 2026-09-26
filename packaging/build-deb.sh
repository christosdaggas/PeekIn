#!/bin/bash
# Build a native Debian package from this tree without changing Fedora files.
# Result: dist/deb/peekin_<version>_<architecture>.deb
set -euo pipefail
umask 022
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -n 1)"
ARCH="$(dpkg --print-architecture)"
MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
OUT="$ROOT/dist/deb"

fail() { echo "error: $*" >&2; exit 1; }
for cmd in cargo rustc pkg-config dpkg-deb dpkg-shlibdeps msgfmt; do
    command -v "$cmd" >/dev/null || fail "missing $cmd (install cargo rustc pkg-config dpkg-dev gettext)"
done
pkg-config --exists opencv4 gtk4 libadwaita-1 ||
    fail 'missing native headers (install libopencv-dev libgtk-4-dev libadwaita-1-dev)'
test -f "/usr/lib/$MULTIARCH/libpam.so" || fail 'missing libpam0g-dev'
dpkg-query -W -f='${Status}' libclang-dev 2>/dev/null | grep -q 'install ok installed' ||
    fail 'missing libclang-dev (needed by opencv-rust bindgen)'

# Stage on a real Unix filesystem: VirtualBox shared folders do not preserve
# ownership/modes, which dpkg-deb needs for PAM, maintainer scripts and data.
STAGE="$(mktemp -d /tmp/opencode/peekin-deb.XXXXXX)"
DEST="$OUT/peekin_${VERSION}-1_${ARCH}.deb"
PARTIAL="$OUT/.peekin_${VERSION}-1_${ARCH}.deb.partial"
trap 'rm -rf "$STAGE"; rm -f "$PARTIAL"' EXIT
PKG="$STAGE/pkg"
# Cargo build scripts create and include generated files; VirtualBox shared
# folders cannot reliably support those operations. Keep the reusable build
# directory on a local filesystem as well as the package staging area.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/opencode/peekin-cargo-target}"
MODELS="$ROOT/target/deb-models"
mkdir -p "$MODELS" "$PKG/DEBIAN" "$OUT"
for model in face_detection_yunet_2023mar.onnx face_recognition_sface_2021dec.onnx; do
    if [ ! -f "$MODELS/$model" ] && [ -f "$ROOT/target/rpmbuild/SOURCES/$model" ]; then
        cp "$ROOT/target/rpmbuild/SOURCES/$model" "$MODELS/$model"
    fi
done
"$ROOT/data/fetch-models.sh" "$MODELS"

echo '>>> Building Debian-native binaries'
cargo build --release --locked --workspace --manifest-path "$ROOT/Cargo.toml"
for binary in peekin peekin-settings; do
    install -Dm755 "$CARGO_TARGET_DIR/release/$binary" "$PKG/usr/bin/$binary"
done
for binary in peekin-helper peekin-compare peekin-session; do
    install -Dm755 "$CARGO_TARGET_DIR/release/$binary" "$PKG/usr/libexec/peekin/$binary"
done
install -Dm755 "$CARGO_TARGET_DIR/release/libpam_peekin.so" "$PKG/usr/lib/$MULTIARCH/security/pam_peekin.so"
install -Dm755 "$ROOT/packaging/deb/pam-setup" "$PKG/usr/libexec/peekin/debian-pam-setup"
install -Dm644 "$ROOT/data/config.ini" "$PKG/etc/peekin/config.ini"
install -Dm644 "$ROOT/data/peekin.sysusers" "$PKG/usr/lib/sysusers.d/peekin.conf"
install -Dm644 "$ROOT/data/peekin.tmpfiles" "$PKG/usr/lib/tmpfiles.d/peekin.conf"
install -Dm644 "$ROOT/data/systemd/peekin-models.service" "$PKG/usr/lib/systemd/system/peekin-models.service"
install -Dm644 "$ROOT/data/systemd/peekin-session.service" "$PKG/usr/lib/systemd/user/peekin-session.service"
for model in "$MODELS"/*.onnx; do
    install -Dm644 "$model" "$PKG/usr/share/peekin/models/$(basename "$model")"
done
install -Dm644 "$ROOT/data/com.chrisdaggas.peekin.policy" "$PKG/usr/share/polkit-1/actions/com.chrisdaggas.peekin.policy"
install -Dm644 "$ROOT/data/com.chrisdaggas.peekin.desktop" "$PKG/usr/share/applications/com.chrisdaggas.peekin.desktop"
install -Dm644 "$ROOT/data/icons/hicolor/scalable/apps/com.chrisdaggas.peekin.svg" "$PKG/usr/share/icons/hicolor/scalable/apps/com.chrisdaggas.peekin.svg"
for page in "$ROOT"/data/man/*.[158]; do
    install -Dm644 "$page" "$PKG/usr/share/man/man${page##*.}/$(basename "$page")"
done
for po in "$ROOT"/po/*.po; do
    lang="$(basename "$po" .po)"
    install -d -m755 "$PKG/usr/share/locale/$lang/LC_MESSAGES"
    msgfmt --check -o "$PKG/usr/share/locale/$lang/LC_MESSAGES/peekin.mo" "$po"
    chmod 0644 "$PKG/usr/share/locale/$lang/LC_MESSAGES/peekin.mo"
done
install -Dm644 "$ROOT/LICENSE" "$PKG/usr/share/doc/peekin/copyright"
install -Dm644 "$ROOT/README.md" "$PKG/usr/share/doc/peekin/README.md"
for script in postinst prerm; do
    install -m755 "$ROOT/packaging/deb/$script" "$PKG/DEBIAN/$script"
done
printf '%s\n' '/etc/peekin/config.ini' > "$PKG/DEBIAN/conffiles"

# Let Debian's shlibs/symbols metadata choose compatible ABI dependencies,
# including OpenCV and GTK, instead of hard-coding Fedora sonames.
mkdir -p "$STAGE/debian"
printf 'Source: peekin\n\nPackage: peekin\nArchitecture: any\nDescription: Face authentication\n' > "$STAGE/debian/control"
SHLIBS="$(cd "$STAGE" && dpkg-shlibdeps -O -e"$PKG/usr/bin/peekin" -e"$PKG/usr/bin/peekin-settings" \
    -e"$PKG/usr/libexec/peekin/peekin-compare" \
    -e"$PKG/usr/libexec/peekin/peekin-session" \
    -e"$PKG/usr/libexec/peekin/peekin-helper" \
    -e"$PKG/usr/lib/$MULTIARCH/security/pam_peekin.so")"
DEPENDS="${SHLIBS#shlibs:Depends=}, systemd, polkitd, passwd"
SIZE="$(du -sk "$PKG" | cut -f1)"
{
    printf 'Package: peekin\nVersion: %s-1\nArchitecture: %s\n' "$VERSION" "$ARCH"
    printf 'Maintainer: Christos A. Daggas <info@chrisdaggas.com>\n'
    printf 'Installed-Size: %s\nDepends: %s\n' "$SIZE" "$DEPENDS"
    printf 'Section: admin\nPriority: optional\n'
    printf 'Description: Local face authentication for Linux\n'
    printf ' PeekIn adds face recognition to sudo and GNOME login via a PAM module.\n'
    printf ' It includes a GTK settings app, session service and offline face models.\n'
} > "$PKG/DEBIAN/control"

dpkg-deb --root-owner-group --build "$PKG" "$PARTIAL"
mv -f "$PARTIAL" "$DEST"
echo ">>> Built: $DEST"
