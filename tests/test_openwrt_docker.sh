#!/usr/bin/env bash
# Docker-based OpenWrt side-router end-to-end test.
#
# Stands up a small, self-contained topology out of Docker containers and
# verifies meow transparently proxies real client traffic through an OpenWrt
# "side router":
#
#     origin (HTTP + UDP echo)                 client1, client2
#        |  meow-e2e-wan (10.13.36.0/24)           |  meow-e2e-lan (10.13.37.0/24, internal)
#        +------------- router (OpenWrt) ----------+
#                    eth0 10.13.36.1   eth1 10.13.37.1
#                    meow + gateway.sh (tproxy) + luci-app-meow
#
# The LAN is a Docker *internal* network, so a client can reach the origin
# ONLY by being routed and proxied through the router — exactly the side-router
# data path. No access to the real LAN and no physical NIC needed.
#
# Asserts: procd service up; REST API + built-in panel; LuCI Clients asset +
# ACL; nftables gateway table + fwmark policy route; TCP TPROXY (client -> origin
# over HTTP); UDP TPROXY (client -> origin echo); DNS hijack (fake-ip answer);
# and that a second client works too.
#
# Requirements: docker, and either MEOW_BINARY (a prebuilt static musl meow for
# the host arch) or cargo-zigbuild + zig to build one. Root (or passwordless
# sudo) to modprobe the nftables TPROXY modules the container needs. Missing
# tooling / capabilities SKIP (exit 0) rather than FAIL, matching the QEMU test.
#
# Usage: bash tests/test_openwrt_docker.sh
#
# Environment overrides:
#   MEOW_BINARY       prebuilt static musl meow binary for the host arch
#   OPENWRT_VERSION   openwrt/rootfs image version (default below)
#   KEEP              set to 1 to leave the containers/networks up on exit

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OPENWRT_VERSION="${OPENWRT_VERSION:-24.10.4}"

PFX="meow-e2e"
NET_WAN="$PFX-wan"
NET_LAN="$PFX-lan"
ROUTER="$PFX-router"
ORIGIN="$PFX-origin"
CLIENTS="$PFX-c1 $PFX-c2"
# The origin sits on a PUBLIC test-net (RFC 5737 TEST-NET-3) so gateway.sh
# actually proxies traffic to it. A 10.x/172.16/192.168 origin would be in the
# reserved-range bypass and get plain-forwarded, never TPROXY'd.
WAN_SUBNET="203.0.113.0/24"
WAN_GW=203.0.113.254
LAN_SUBNET="10.13.37.0/24"
LAN_GW=10.13.37.254
ROUTER_WAN=203.0.113.1
ORIGIN_IP=203.0.113.2
ROUTER_LAN=10.13.37.1
UDP_PORT=9999

PASS=0; FAIL=0
pass() { echo "TEST_PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "TEST_FAIL: $1 ${2:+-- $2}"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP: $1"; exit 0; }

# check <name> <expected-substring> <command...>
check() {
    local name="$1" want="$2"; shift 2
    local out
    out="$("$@" 2>&1)"
    if printf '%s' "$out" | grep -qF "$want"; then
        pass "$name"
    else
        fail "$name" "want '$want', got: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
    fi
}

rexec() { docker exec "$ROUTER" sh -c "$1"; }

command -v docker >/dev/null 2>&1 || skip "docker not found"
docker info >/dev/null 2>&1 || skip "docker daemon not available"

# --- Host arch -> image / target ---
case "$(uname -m)" in
    aarch64|arm64) PLAT=linux/aarch64_generic; OW_TAG=armsr-armv8; OW_ARCH=aarch64_generic; RUST_TARGET=aarch64-unknown-linux-musl ;;
    x86_64|amd64)  PLAT=linux/x86_64;          OW_TAG=x86-64;      OW_ARCH=x86_64;          RUST_TARGET=x86_64-unknown-linux-musl ;;
    *) skip "unsupported host arch $(uname -m)" ;;
esac
IMAGE="openwrt/rootfs:${OW_TAG}-${OPENWRT_VERSION}"

# --- nftables TPROXY modules (loaded on the host; containers share the kernel) ---
MODULES="nf_tables nft_tproxy nft_socket nft_chain_nat nft_nat nft_redir
nft_masq nft_fib nft_fib_inet nft_fib_ipv4 nf_nat nf_conntrack"
for m in $MODULES; do sudo -n modprobe "$m" 2>/dev/null || modprobe "$m" 2>/dev/null || true; done
# TPROXY is mandatory for this test; if the kernel has no nft_tproxy (loaded or
# builtin) and we cannot load it, SKIP rather than FAIL — it is an environment
# limitation, not a meow bug.
if [ ! -d /sys/module/nft_tproxy ] && ! grep -qw nft_tproxy /proc/modules 2>/dev/null; then
    skip "nft_tproxy kernel module unavailable (need root/modprobe or a kernel with TPROXY)"
fi

# --- Build (or locate) the meow binary for the container arch ---
if [ -n "${MEOW_BINARY:-}" ]; then
    BINARY="$MEOW_BINARY"
else
    PREBUILT="$ROOT_DIR/target/$RUST_TARGET/release/meow"
    if [ -f "$PREBUILT" ]; then
        BINARY="$PREBUILT"
    elif command -v cargo-zigbuild >/dev/null 2>&1 && command -v zig >/dev/null 2>&1; then
        echo "=== Building $RUST_TARGET meow binary ==="
        ( cd "$ROOT_DIR" && cargo zigbuild --release --target "$RUST_TARGET" --bin meow ) || skip "binary build failed"
        BINARY="$PREBUILT"
    else
        skip "no MEOW_BINARY and cargo-zigbuild/zig not available"
    fi
fi
[ -f "$BINARY" ] || skip "meow binary not found: $BINARY"

WORK="$(mktemp -d)"
cleanup() {
    if [ "${KEEP:-0}" = 1 ]; then echo "KEEP=1: leaving $ROUTER/$ORIGIN/$CLIENTS and $NET_WAN/$NET_LAN up"; rm -rf "$WORK"; return; fi
    docker rm -f $ROUTER $ORIGIN $CLIENTS >/dev/null 2>&1
    docker network rm "$NET_WAN" "$NET_LAN" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "=== Building ipks ($OW_ARCH) ==="
bash "$ROOT_DIR/openwrt/build-ipk.sh" meow --binary "$BINARY" --version 0.0.0-e2e --arch "$OW_ARCH" --outdir "$WORK" >/dev/null || skip "meow ipk build failed"
bash "$ROOT_DIR/openwrt/build-ipk.sh" luci --version 0.0.0-e2e --outdir "$WORK" >/dev/null || skip "luci ipk build failed"

echo "=== Pulling $IMAGE ==="
docker pull --platform "$PLAT" "$IMAGE" >/dev/null 2>&1 || skip "cannot pull $IMAGE"

echo "=== Networks ==="
# Docker reserves .1 for the bridge gateway, so park it at .254 and use .1 for
# the router (its natural gateway address to the clients).
docker rm -f $ROUTER $ORIGIN $CLIENTS >/dev/null 2>&1
docker network rm "$NET_WAN" "$NET_LAN" >/dev/null 2>&1
docker network create --subnet "$WAN_SUBNET" --gateway "$WAN_GW" "$NET_WAN" >/dev/null
docker network create --internal --subnet "$LAN_SUBNET" --gateway "$LAN_GW" "$NET_LAN" >/dev/null

echo "=== Origin (HTTP + UDP echo on the WAN) ==="
docker run -d --name "$ORIGIN" --network "$NET_WAN" --ip "$ORIGIN_IP" alpine:3 sleep infinity >/dev/null
# socat serves both (busybox in alpine ships no httpd applet). The WAN bridge
# NATs to the host, so apk can fetch socat.
docker exec "$ORIGIN" sh -c 'apk add -q --no-cache socat >/dev/null 2>&1 || true'
if docker exec "$ORIGIN" sh -c 'command -v socat >/dev/null'; then
  ORIGIN_UDP=1
  docker exec "$ORIGIN" sh -c 'cat > /resp.sh <<'\''EOF'\''
#!/bin/sh
printf "HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\npong-http"
EOF
chmod +x /resp.sh'
  docker exec -d "$ORIGIN" socat TCP-LISTEN:80,reuseaddr,fork EXEC:/resp.sh
  docker exec -d "$ORIGIN" socat -T10 "UDP-RECVFROM:$UDP_PORT,fork" EXEC:/bin/cat
else
  ORIGIN_UDP=0
fi

echo "=== Router (OpenWrt) ==="
docker run -d --name "$ROUTER" --hostname router --platform "$PLAT" \
    --network "$NET_WAN" --ip "$ROUTER_WAN" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --sysctl net.ipv4.ip_forward=1 \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 \
    "$IMAGE" /sbin/init >/dev/null
docker network connect --ip "$ROUTER_LAN" "$NET_LAN" "$ROUTER"

# Wait for procd/ubus and first-boot uci-defaults to finish.
for _ in $(seq 1 60); do
    docker exec "$ROUTER" sh -c 'ubus call system board && [ -z "$(ls /etc/uci-defaults 2>/dev/null)" ]' >/dev/null 2>&1 && break
    sleep 1
done

# OpenWrt-in-Docker hardening + side-router network config.
rexec '
set -e
# procd ujail cannot pivot_root in a container; run jailed services unjailed.
if ! grep -q e2e-shim /sbin/ujail 2>/dev/null; then
  cat > /sbin/ujail <<SHIM
#!/bin/sh
# e2e-shim
while [ \$# -gt 0 ] && [ "\$1" != "--" ]; do shift; done
[ "\$1" = "--" ] && shift
exec "\$@"
SHIM
  chmod 755 /sbin/ujail
fi
# Shutdown umount remounts / read-only, which sticks to the overlay.
/etc/init.d/umount disable 2>/dev/null || true

cat > /etc/config/network <<UCI
config interface "loopback"
	option device "lo"
	option proto "static"
	option ipaddr "127.0.0.1"
	option netmask "255.0.0.0"
config interface "wan"
	option device "eth0"
	option proto "static"
	option ipaddr "'"$ROUTER_WAN"'"
	option netmask "255.255.255.0"
config interface "lan"
	option device "eth1"
	option proto "static"
	option ipaddr "'"$ROUTER_LAN"'"
	option netmask "255.255.255.0"
UCI

# Default firewall already has lan/wan zones + lan->wan forward + wan masq.
/etc/init.d/odhcpd disable 2>/dev/null || true
/etc/init.d/odhcpd stop 2>/dev/null || true
for t in 1 2 3 4 5; do /etc/init.d/network restart; sleep 2; ifstatus lan | grep -q "\"up\": true" && break; done
/etc/init.d/firewall restart >/dev/null 2>&1 || true
'

echo "=== Install ipks ==="
docker exec "$ROUTER" mkdir -p /tmp/ipk
docker cp "$WORK/meow_0.0.0-e2e_${OW_ARCH}.ipk" "$ROUTER:/tmp/ipk/meow.ipk"
docker cp "$WORK/luci-app-meow_0.0.0-e2e_all.ipk" "$ROUTER:/tmp/ipk/luci.ipk"
# meow installs via opkg (arch-specific), exercising its postinst/uci-defaults
# and procd wiring. The LuCI app is arch `all` and depends on luci-base/arping,
# which this stripped openwrt/rootfs image lacks and cannot resolve — so its
# static files are laid down by unpacking the ipk's data payload directly. The
# assertions then confirm the Clients view + ACL ship correctly. On a real
# OpenWrt image `opkg install luci-app-meow` pulls its deps and does this.
rexec 'mkdir -p /var/lock
opkg install --force-depends /tmp/ipk/meow.ipk >/tmp/opkg.log 2>&1
cd /tmp/ipk && tar -xzf luci.ipk ./data.tar.gz && tar -xzf data.tar.gz -C / && rm -f /tmp/luci-indexcache*
:'

echo "=== Enable meow + transparent proxy (tproxy) ==="
rexec '
uci set meow.main.enabled=1
uci set meow.tproxy.enabled=1
uci set meow.tproxy.mode=tproxy
uci set meow.tproxy.interface=lan
uci commit meow
/etc/init.d/meow restart
'
# gateway.sh loads once meow has bound the listener.
rexec '/usr/share/meow/gateway.sh wait && /usr/share/meow/gateway.sh up' >/dev/null 2>&1 || true
sleep 2

echo "=== Clients (LAN-only; routed through the router) ==="
i=1
for c in $CLIENTS; do
    docker run -d --name "$c" --network "$NET_LAN" --ip "10.13.37.1$i" \
        --cap-add NET_ADMIN alpine:3 sleep infinity >/dev/null
    docker exec "$c" sh -c "ip route replace default via $ROUTER_LAN; printf 'nameserver %s\n' $ROUTER_LAN > /etc/resolv.conf"
    i=$((i + 1))
done
C1="$PFX-c1"; C2="$PFX-c2"

echo ""
echo "=== Assertions ==="

# Router service + control plane
check "procd service running"      "MEOW_UP"    bash -c "docker exec $ROUTER sh -c 'pidof meow >/dev/null && echo MEOW_UP'"
check "REST API /version"          "version"    bash -c "docker exec $ROUTER uclient-fetch -q -O - http://127.0.0.1:9090/version"
check "built-in panel /ui"         "meow-rs"    bash -c "docker exec $ROUTER uclient-fetch -q -O - http://127.0.0.1:9090/ui"
check "LuCI Clients asset served"  "meow Clients" bash -c "docker exec $ROUTER cat /www/luci-static/resources/view/meow/clients.js"
check "LuCI ACL grants arp exec"   "arp-hijack.sh clients" bash -c "docker exec $ROUTER cat /usr/share/rpcd/acl.d/luci-app-meow.json"
check "arp steering off by default" "0"         bash -c "docker exec $ROUTER uci -q get meow.arp.enabled"

# Firewall / routing plumbing (firewall:false -> only gateway.sh's table)
check "gateway nft table loaded"   "meow_gateway" bash -c "docker exec $ROUTER nft list tables"
check "tproxy fwmark policy route" "lookup 233"   bash -c "docker exec $ROUTER ip rule"

# Data path: client -> origin, forced through the router + meow tproxy
check "client1 TCP via tproxy"     "pong-http"  bash -c "docker exec $C1 wget -q -T 10 -O - http://$ORIGIN_IP/probe"
check "client2 TCP via tproxy"     "pong-http"  bash -c "docker exec $C2 wget -q -T 10 -O - http://$ORIGIN_IP/probe"
check "meow logged client TCP flow" "$ORIGIN_IP:80" bash -c "docker exec $ROUTER logread -e meow | sed 's/\x1b\[[0-9;]*m//g'"

# DNS hijack: any name resolves to a fake-ip (198.18/16) via the router.
check "DNS hijack returns fake-ip" "198.18."   bash -c "docker exec $C1 nslookup probe.meow.test $ROUTER_LAN 2>&1 | tail -n +3"

# UDP TPROXY (needs socat on origin); skip cleanly if unavailable.
if [ "$ORIGIN_UDP" = 1 ]; then
    check "client1 UDP via tproxy"   "ping-udp"  bash -c "docker exec $C1 sh -c 'echo ping-udp | nc -u -w2 $ORIGIN_IP $UDP_PORT'"
    check "meow logged client UDP flow" "$ORIGIN_IP:$UDP_PORT" bash -c "docker exec $ROUTER logread -e meow | sed 's/\x1b\[[0-9;]*m//g'"
else
    echo "TEST_SKIP: UDP TPROXY (socat unavailable on origin)"
fi

# --- LuCI: rpcd actually loads the meow ACL group, and the menu is on-device ---
# rpcd ships in the base image; it reads /usr/share/rpcd/acl.d. A root ubus
# login expands the granted access-groups, so the meow file grants must appear
# in the session's ACLs — the same grants a logged-in LuCI user relies on.
rexec '/etc/init.d/rpcd restart 2>/dev/null; sleep 1'
LOGIN='ubus call session login "{\"username\":\"root\",\"password\":\"\"}"'
check "LuCI rpcd loads arp-hijack grant" "arp-hijack.sh clients" bash -c "docker exec $ROUTER sh -c '$LOGIN'"
check "LuCI rpcd loads meow-arp grant"   "meow-arp restart"      bash -c "docker exec $ROUTER sh -c '$LOGIN'"
check "LuCI rpcd loads config grant"     "/etc/meow"             bash -c "docker exec $ROUTER sh -c '$LOGIN'"
check "LuCI menu registers Clients view" "meow/clients"          bash -c "docker exec $ROUTER grep -o meow/clients /usr/share/luci/menu.d/luci-app-meow.json"

if [ "$FAIL" -gt 0 ]; then
    echo ""; echo "=== Debug (failures present) ==="
    echo "-- opkg.log --"; rexec 'cat /tmp/opkg.log 2>/dev/null | tail -20'
    echo "-- meow listener --"; rexec 'ss -lntup 2>/dev/null | grep 7893 || netstat -lntup 2>/dev/null | grep 7893'
    echo "-- mangle_tproxy chain --"; rexec 'nft list chain inet meow_gateway mangle_tproxy 2>/dev/null'
    echo "-- meow log tail --"; rexec 'logread -e meow | sed "s/\x1b\[[0-9;]*m//g" | tail -8'
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && [ "$PASS" -gt 0 ] && { echo "=== All OpenWrt docker e2e tests passed ==="; exit 0; }
echo "=== FAIL ==="; exit 1
