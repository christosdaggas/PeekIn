#!/bin/bash
# Download the OpenCV face models used by PeekIn and verify their checksums.
# Usage: fetch-models.sh [target-dir]   (default: /usr/share/peekin/models)
# Files already present with the right checksum are kept, so repeated package
# builds do not download them again.
set -euo pipefail

TARGET="${1:-/usr/share/peekin/models}"
# The models are Git LFS objects: try the LFS media host directly, then the
# repository's raw URL (which redirects to it).
MIRRORS=(
    https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models
    https://github.com/opencv/opencv_zoo/raw/main/models
)

declare -A MODELS=(
    [face_detection_yunet_2023mar.onnx]="face_detection_yunet 8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4"
    [face_recognition_sface_2021dec.onnx]="face_recognition_sface 0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79"
)

mkdir -p "$TARGET"
for name in "${!MODELS[@]}"; do
    read -r dir sha <<< "${MODELS[$name]}"
    if [ -f "$TARGET/$name" ] && echo "$sha  $TARGET/$name" | sha256sum -c --status; then
        echo "Using existing $name"
        continue
    fi
    tmp="$(mktemp "$TARGET/.$name.XXXXXX")"
    trap 'rm -f "$tmp"' EXIT
    ok=0
    for base in "${MIRRORS[@]}"; do
        host=${base#https://}; echo "Downloading $name from ${host%%/*}"
        if curl -fsSL --retry 3 -o "$tmp" "$base/$dir/$name" &&
            echo "$sha  $tmp" | sha256sum -c --status; then
            ok=1
            break
        fi
    done
    if [ "$ok" != 1 ]; then
        echo "Could not download $name with the expected checksum, refusing to install it" >&2
        exit 1
    fi
    chmod 644 "$tmp"
    mv "$tmp" "$TARGET/$name"
    trap - EXIT
done
echo "Models installed in $TARGET"
