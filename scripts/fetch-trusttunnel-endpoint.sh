#!/usr/bin/env bash
# Official test-only peer, pinned version and archive SHA-256.
set -euo pipefail

destination="${1:?usage: fetch-trusttunnel-endpoint.sh <output-directory>}"
version="1.1.0"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    platform="linux-x86_64"
    asset_id="539485496"
    checksum="91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7"
    ;;
  Linux:aarch64|Linux:arm64)
    platform="linux-aarch64"
    asset_id="539485498"
    checksum="c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686"
    ;;
  Darwin:arm64|Darwin:x86_64)
    platform="macos-universal"
    asset_id="539485500"
    checksum="126a5688e922ce8f83d4de2d8a2659b3aab97820184d30f2edbecc0ec4a32ae5"
    ;;
  *) printf 'Unsupported endpoint test platform\n' >&2; exit 1 ;;
esac

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
archive="trusttunnel-v${version}-${platform}.tar.gz"
if ! curl --fail --location --retry 3 --connect-timeout 15 --max-time 180 --proto '=https' --tlsv1.2 \
  "https://github.com/TrustTunnel/TrustTunnel/releases/download/v${version}/${archive}" \
  --output "$temporary/$archive"; then
  curl --fail --location --retry 3 --connect-timeout 15 --max-time 180 --proto '=https' --tlsv1.2 \
    -H 'Accept: application/octet-stream' -H 'User-Agent: meow-trusttunnel-e2e' \
    "https://api.github.com/repos/TrustTunnel/TrustTunnel/releases/assets/${asset_id}?download=1" \
    --output "$temporary/$archive"
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$temporary/$archive" | cut -d ' ' -f 1)"
else
  actual="$(shasum -a 256 "$temporary/$archive" | cut -d ' ' -f 1)"
fi
test "$actual" = "$checksum" || { printf 'Endpoint archive SHA256 mismatch\n' >&2; exit 1; }
tar -xzf "$temporary/$archive" -C "$temporary"
mkdir -p "$destination"
cp "$temporary/trusttunnel-v${version}-${platform}/trusttunnel_endpoint" \
  "$destination/trusttunnel_endpoint"
chmod +x "$destination/trusttunnel_endpoint"
printf 'Official TrustTunnel v%s (%s), SHA256 verified\n' "$version" "$platform"
