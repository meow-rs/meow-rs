#!/usr/bin/env bash
# Assemble OpenWrt .ipk packages (opkg format) without the OpenWrt SDK.
#
# The release binaries are fully static musl builds, so a single Rust target
# serves several OpenWrt architecture labels; the ipk only differs in the
# `Architecture:` control field. Works with both GNU tar and bsdtar (macOS).
#
# Usage:
#   build-ipk.sh meow --binary <path> --version <ver> --arch <openwrt-arch> [--outdir <dir>]
#   build-ipk.sh luci --version <ver> [--outdir <dir>]
#
# Examples:
#   build-ipk.sh meow --binary target/aarch64-unknown-linux-musl/release/meow \
#       --version 0.16.0 --arch aarch64_generic --outdir dist
#   build-ipk.sh luci --version 0.16.0 --outdir dist

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAINTAINER="Max Lv <max.c.lv@gmail.com>"

usage() {
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

# tar flags forcing root ownership: GNU tar and bsdtar spell them differently.
# --format=ustar is mandatory: bsdtar's default (restricted pax) emits
# extended-header entries that opkg's untar skips silently, producing an
# "installed" package with no files on the device.
if tar --version 2>/dev/null | grep -q "GNU tar"; then
    TAR_OWNER=(--format=ustar --owner=0 --group=0 --numeric-owner)
else
    TAR_OWNER=(--format=ustar --uid 0 --gid 0 --numeric-owner)
fi

# pack_ipk <staging-dir> <output-file>
# <staging-dir> must contain control/ (control, conffiles, postinst, ...)
# and data/ (the target filesystem tree).
pack_ipk() {
    local staging="$1" out="$2"

    printf '2.0\n' > "${staging}/debian-binary"
    tar -C "${staging}/control" "${TAR_OWNER[@]}" -czf "${staging}/control.tar.gz" .
    tar -C "${staging}/data" "${TAR_OWNER[@]}" -czf "${staging}/data.tar.gz" .
    # opkg expects members in this exact order.
    tar -C "${staging}" "${TAR_OWNER[@]}" -czf "${out}" \
        ./debian-binary ./control.tar.gz ./data.tar.gz
    echo "built ${out}"
}

# installed_size <data-dir>
installed_size() {
    find "$1" -type f -exec wc -c {} + | awk 'END { print $1 }'
}

build_meow() {
    local binary="" version="" arch="" outdir="."
    while [ $# -gt 0 ]; do
        case "$1" in
            --binary)  binary="$2"; shift 2 ;;
            --version) version="$2"; shift 2 ;;
            --arch)    arch="$2"; shift 2 ;;
            --outdir)  outdir="$2"; shift 2 ;;
            *) echo "unknown option: $1" >&2; usage ;;
        esac
    done
    [ -n "$binary" ] && [ -n "$version" ] && [ -n "$arch" ] || usage
    [ -f "$binary" ] || { echo "binary not found: $binary" >&2; exit 1; }

    local staging
    staging="$(mktemp -d)"
    mkdir -p "$staging/control" \
             "$staging/data/usr/bin" \
             "$staging/data/etc/init.d" \
             "$staging/data/etc/config" \
             "$staging/data/etc/meow" \
             "$staging/data/etc/uci-defaults" \
             "$staging/data/usr/share/meow"

    install -m 755 "$binary" "$staging/data/usr/bin/meow"
    install -m 755 "$SCRIPT_DIR/meow/files/meow.init" "$staging/data/etc/init.d/meow"
    install -m 644 "$SCRIPT_DIR/meow/files/meow.config" "$staging/data/etc/config/meow"
    install -m 644 "$SCRIPT_DIR/meow/files/config.yaml" "$staging/data/etc/meow/config.yaml"
    install -m 755 "$SCRIPT_DIR/meow/files/gateway.sh" "$staging/data/usr/share/meow/gateway.sh"
    install -m 755 "$SCRIPT_DIR/meow/files/arp-hijack.sh" "$staging/data/usr/share/meow/arp-hijack.sh"
    install -m 755 "$SCRIPT_DIR/meow/files/meow-arp.init" "$staging/data/etc/init.d/meow-arp"
    install -m 755 "$SCRIPT_DIR/meow/files/meow.uci-defaults" "$staging/data/etc/uci-defaults/80_meow"

    cat > "$staging/control/control" <<EOF
Package: meow
Version: ${version}
Depends: libc
Section: net
Architecture: ${arch}
Installed-Size: $(installed_size "$staging/data")
Maintainer: ${MAINTAINER}
Description:  A high-performance, rule-based tunneling proxy kernel in Rust,
  compatible with mihomo (Clash Meta). Static binary; configuration lives in
  /etc/meow/config.yaml, service settings in /etc/config/meow.
EOF

    cat > "$staging/control/conffiles" <<EOF
/etc/config/meow
/etc/meow/config.yaml
EOF

    cat > "$staging/control/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
[ -f /etc/uci-defaults/80_meow ] && sh /etc/uci-defaults/80_meow && rm -f /etc/uci-defaults/80_meow
/etc/init.d/meow enable || true
# meow-arp self-gates on the (default-off) arp_hijack section, so enabling it
# is safe: it steers nothing until clients are selected in LuCI.
/etc/init.d/meow-arp enable || true
exit 0
EOF

    cat > "$staging/control/prerm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/meow-arp stop 2>/dev/null
/etc/init.d/meow-arp disable 2>/dev/null
/etc/init.d/meow stop 2>/dev/null
/etc/init.d/meow disable || true
exit 0
EOF

    chmod 755 "$staging/control/postinst" "$staging/control/prerm"

    mkdir -p "$outdir"
    pack_ipk "$staging" "${outdir}/meow_${version}_${arch}.ipk"
    rm -rf "$staging"
}

build_luci() {
    local version="" outdir="."
    while [ $# -gt 0 ]; do
        case "$1" in
            --version) version="$2"; shift 2 ;;
            --outdir)  outdir="$2"; shift 2 ;;
            *) echo "unknown option: $1" >&2; usage ;;
        esac
    done
    [ -n "$version" ] || usage

    local staging app="$SCRIPT_DIR/luci-app-meow"
    staging="$(mktemp -d)"
    mkdir -p "$staging/control" "$staging/data/www/luci-static" "$staging/data"

    # htdocs/ maps to /www, root/ overlays / verbatim.
    cp -R "$app/root/." "$staging/data/"
    cp -R "$app/htdocs/luci-static/." "$staging/data/www/luci-static/"
    find "$staging/data" -type d -exec chmod 755 {} +
    find "$staging/data" -type f -exec chmod 644 {} +

    cat > "$staging/control/control" <<EOF
Package: luci-app-meow
Version: ${version}
Depends: libc, luci-base, meow
Section: luci
Architecture: all
Installed-Size: $(installed_size "$staging/data")
Maintainer: ${MAINTAINER}
Description:  LuCI support for meow: status overview, YAML config editor,
  service and transparent-proxy (gateway / side-router) settings, ARP-based
  client steering, logs, and the built-in meow web panel embedded in LuCI.
  The optional client-steering feature needs the arping package at runtime.
EOF

    cat > "$staging/control/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache* 2>/dev/null
/etc/init.d/rpcd reload 2>/dev/null
exit 0
EOF

    cat > "$staging/control/postrm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache* 2>/dev/null
exit 0
EOF

    chmod 755 "$staging/control/postinst" "$staging/control/postrm"

    mkdir -p "$outdir"
    pack_ipk "$staging" "${outdir}/luci-app-meow_${version}_all.ipk"
    rm -rf "$staging"
}

case "${1:-}" in
    meow) shift; build_meow "$@" ;;
    luci) shift; build_luci "$@" ;;
    *) usage ;;
esac
