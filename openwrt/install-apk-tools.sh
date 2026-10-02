#!/usr/bin/env bash
# Install a pinned, static apk-tools 3 binary (for `apk mkpkg`, used by
# build-apk.sh) into <dir>/apk. Linux x86_64 / aarch64 only.
#
# The binary comes from Alpine's `apk-tools-static` package, Alpine's own
# bootstrap channel for apk. gitlab.alpinelinux.org (the source repo) sits
# behind bot protection that rejects CI clones, so building from source is not
# reliable from GitHub runners. The download is verified against the sha256
# pinned below.
#
# Alpine's CDN only keeps the current build of each package, so a stale pin
# fails loudly (404 or checksum mismatch). To bump: pick the new version from
# https://dl-cdn.alpinelinux.org/alpine/<branch>/main/<arch>/, update the four
# variables below, and refresh both sha256 values with `sha256sum`.
#
# Usage: install-apk-tools.sh <dir>
#   If <dir>/apk already reports the pinned version, nothing is downloaded
#   (so the directory can be cached between CI runs).

set -euo pipefail

APK_TOOLS_VERSION="3.0.8-r0"
ALPINE_BRANCH="v3.24"
SHA256_X86_64="c8e2c88c13ba12a12269b79a3543e1190ff8c0ab0beb32b58cadfd5881c619e3"
SHA256_AARCH64="7e86f8258f3a97ea1c279105950ebf6c9af960891eb499f731b7e5f0af26ff63"

dest="${1:?usage: install-apk-tools.sh <dir>}"

case "$(uname -m)" in
    x86_64)          arch=x86_64;  want="$SHA256_X86_64" ;;
    aarch64 | arm64) arch=aarch64; want="$SHA256_AARCH64" ;;
    *) echo "install-apk-tools.sh: unsupported host arch $(uname -m)" >&2; exit 1 ;;
esac

# `apk --version` prints e.g. "apk-tools 3.0.8-r0, compiled for x86_64."
if [ -x "$dest/apk" ] && "$dest/apk" --version 2>/dev/null | grep -q "^apk-tools ${APK_TOOLS_VERSION},"; then
    echo "apk-tools ${APK_TOOLS_VERSION} already present in ${dest}"
    exit 0
fi

mkdir -p "$dest"
pkg="$dest/apk-tools-static-${APK_TOOLS_VERSION}.${arch}.apk"
if [ ! -f "$pkg" ]; then
    curl -fsSL --retry 3 -o "$pkg" \
        "https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/main/${arch}/apk-tools-static-${APK_TOOLS_VERSION}.apk"
fi

got="$(sha256sum "$pkg" | cut -d' ' -f1)"
if [ "$got" != "$want" ]; then
    echo "install-apk-tools.sh: sha256 mismatch for ${pkg}" >&2
    echo "  expected ${want}" >&2
    echo "  got      ${got}" >&2
    rm -f "$pkg"
    exit 1
fi

# The package is a gzip'd tar (signature segment first, which tar ignores).
# GNU tar warns about apk's "unknown extended header keyword"s; harmless.
tar -xzf "$pkg" -C "$dest" sbin/apk.static
mv "$dest/sbin/apk.static" "$dest/apk"
rmdir "$dest/sbin"
rm -f "$pkg"
"$dest/apk" --version
