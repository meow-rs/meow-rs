#!/usr/bin/env bash
# Official test-only peer for v2ray_plugin_integration, pinned version and
# archive SHA-256 (the release publishes no checksums; these were recorded
# when the pin was set). Installs `<output-directory>/v2ray-plugin`.
set -euo pipefail

destination="${1:?usage: fetch-v2ray-plugin.sh <output-directory>}"
version="1.3.2"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    platform="linux-amd64"
    checksum="b578514235b98b230f881aa2a01a7277205f85135bc09fc3832e5f3993ee541a"
    ;;
  Linux:aarch64|Linux:arm64)
    platform="linux-arm64"
    checksum="ef07467cdbd249cdec517809d281ada91c5b4640e7f003a324d145ce1e66fec3"
    ;;
  Darwin:x86_64)
    platform="darwin-amd64"
    checksum="8799690fd9b6179fab6851d6576c5c3f1bf6fc3b321b02b8d5009adb2967b144"
    ;;
  Darwin:arm64)
    platform="darwin-arm64"
    checksum="357476695ec06498cdc38f3a9efd5b99e4d601db4807661117bf3bae917286ae"
    ;;
  *) printf 'Unsupported v2ray-plugin test platform\n' >&2; exit 1 ;;
esac

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
archive="v2ray-plugin-${platform}-v${version}.tar.gz"
curl --fail --location --retry 3 --connect-timeout 15 --max-time 180 --proto '=https' --tlsv1.2 \
  "https://github.com/shadowsocks/v2ray-plugin/releases/download/v${version}/${archive}" \
  --output "$temporary/$archive"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$temporary/$archive" | cut -d ' ' -f 1)"
else
  actual="$(shasum -a 256 "$temporary/$archive" | cut -d ' ' -f 1)"
fi
test "$actual" = "$checksum" || { printf 'v2ray-plugin archive SHA256 mismatch\n' >&2; exit 1; }
member="v2ray-plugin_${platform/-/_}"
tar -xzf "$temporary/$archive" -C "$temporary" "$member"
mkdir -p "$destination"
cp "$temporary/$member" "$destination/v2ray-plugin"
chmod +x "$destination/v2ray-plugin"
printf 'Official v2ray-plugin v%s (%s), SHA256 verified\n' "$version" "$platform"
