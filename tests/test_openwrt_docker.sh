#!/usr/bin/env bash
# Docker-based OpenWrt side-router end-to-end test.
#
# Stands up a small, self-contained topology out of Docker containers and
# verifies meow transparently proxies real client traffic through an OpenWrt
# "side router":
#
#     origin (HTTP + UDP echo)                 client1, client2
#        |  meow-e2e-wan (203.0.113.0/24)           |  meow-e2e-lan (10.13.37.0/24, internal)
#        +------------- router (OpenWrt) ----------+
#                    eth0 203.0.113.1   eth1 10.13.37.1
#                    meow + gateway.sh (tproxy) + luci-app-meow
#
# The LAN is a Docker *internal* network, so a client can reach the origin
# ONLY by being routed and proxied through the router — exactly the side-router
# data path. No access to the real LAN and no physical NIC needed.
#
# Asserts: procd service up; REST API + built-in panel; LuCI Clients asset +
# ACL; nftables gateway table + fwmark policy route; TCP REDIRECT (client -> origin
# over HTTP); UDP TPROXY (client -> origin echo); DNS hijack (fake-ip answer);
# and that a second client works too.
#
# Requirements: docker, and either MEOW_BINARY (a prebuilt static musl meow for
# the Docker server arch) or cargo-zigbuild + zig to build one. The Docker
# host kernel needs nftables TPROXY support. Missing prerequisites skip locally;
# MEOW_REQUIRE_DOCKER=1 (set in CI) makes them fail.
#
# Usage: bash tests/test_openwrt_docker.sh
#
# Environment overrides:
#   MEOW_BINARY       prebuilt static musl meow binary for the host arch
#   OPENWRT_VERSION   openwrt/rootfs image version (default below)
#   MEOW_PACKAGE_PROXY optional HTTP proxy used only for package downloads
#   KEEP              set to 1 to leave the containers/networks up on exit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OPENWRT_VERSION="${OPENWRT_VERSION:-24.10.7}"

PFX="meow-e2e-$$"
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
skip() {
    if [ "${MEOW_REQUIRE_DOCKER:-0}" = 1 ]; then
        echo "FAIL: $1 (Docker coverage is required)"; exit 1
    fi
    echo "SKIP: $1"; exit 0
}

# check <name> <expected-substring> <command...>
check() {
    local name="$1" want="$2"; shift 2
    local out
    local status=0
    out="$("$@" 2>&1)" || status=$?
    if [ "$status" -eq 0 ] && [[ "$out" == *"$want"* ]]; then
        pass "$name"
    else
        fail "$name" "want '$want', got: $(printf '%s' "$out" | tr '\n' '|' | cut -c1-200)"
    fi
}

# Docker client proxy defaults must not redirect this isolated topology's
# requests through a user's host proxy (including package downloads).
PACKAGE_ENV=(-e HTTP_PROXY="${MEOW_PACKAGE_PROXY:-}" -e HTTPS_PROXY="${MEOW_PACKAGE_PROXY:-}"
    -e http_proxy="${MEOW_PACKAGE_PROXY:-}" -e https_proxy="${MEOW_PACKAGE_PROXY:-}")
NO_PROXY_ENV=(-e HTTP_PROXY= -e HTTPS_PROXY= -e ALL_PROXY= -e http_proxy= -e https_proxy= -e all_proxy=)

rexec() { docker exec "$ROUTER" sh -c "unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; $1"; }

command -v docker >/dev/null 2>&1 || skip "docker not found"
docker info >/dev/null 2>&1 || skip "docker daemon not available"

# Docker may be remote or run inside a VM: use its architecture and kernel.
DOCKER_ARCH="$(docker info --format '{{.Architecture}}')"
# These are the architecture names advertised by the OpenWrt rootfs manifests,
# including aarch64_generic (not the usual OCI arm64 spelling).
case "$DOCKER_ARCH" in
    aarch64|arm64) PLAT=linux/aarch64_generic; OW_TAG=armsr-armv8; OW_ARCH=aarch64_generic; RUST_TARGET=aarch64-unknown-linux-musl ;;
    x86_64|amd64)  PLAT=linux/x86_64; OW_TAG=x86-64; OW_ARCH=x86_64; RUST_TARGET=x86_64-unknown-linux-musl ;;
    *) skip "unsupported Docker architecture $DOCKER_ARCH" ;;
esac
IMAGE="openwrt/rootfs:${OW_TAG}-${OPENWRT_VERSION}"

# Linux hosts can load modules explicitly; on Docker Desktop/remote servers,
# the nft rule insertion below checks the actual server kernel instead.
if [ "$(uname -s)" = Linux ]; then
    for m in nf_tables nft_tproxy nft_socket nft_chain_nat nft_nat nft_redir nft_masq nft_fib nft_fib_inet nft_fib_ipv4 nf_nat nf_conntrack; do
        sudo -n modprobe "$m" 2>/dev/null || modprobe "$m" 2>/dev/null || true
    done
fi

# --- Build (or locate) the meow binary for the container arch ---
if [ -n "${MEOW_BINARY:-}" ]; then
    BINARY="$MEOW_BINARY"
else
    command -v cargo-zigbuild >/dev/null 2>&1 && command -v zig >/dev/null 2>&1 ||
        skip "no MEOW_BINARY and cargo-zigbuild/zig not available"
    echo "=== Building $RUST_TARGET meow binary ==="
    ( cd "$ROOT_DIR" && cargo zigbuild --release --target "$RUST_TARGET" --bin meow )
    BINARY="$ROOT_DIR/target/$RUST_TARGET/release/meow"
fi
[ -f "$BINARY" ] || { echo "FAIL: meow binary not found: $BINARY"; exit 1; }

WORK="$(mktemp -d)"
cleanup() {
    if [ "${KEEP:-0}" = 1 ]; then echo "KEEP=1: leaving $ROUTER/$ORIGIN/$CLIENTS and $NET_WAN/$NET_LAN up"; rm -rf "$WORK"; return; fi
    docker rm -f $ROUTER $ORIGIN $CLIENTS >/dev/null 2>&1 || true
    docker network rm "$NET_WAN" "$NET_LAN" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

echo "=== Building ipks ($OW_ARCH) ==="
bash "$ROOT_DIR/openwrt/build-ipk.sh" meow --binary "$BINARY" --version 0.0.0-e2e --arch "$OW_ARCH" --outdir "$WORK" >/dev/null
bash "$ROOT_DIR/openwrt/build-ipk.sh" luci --version 0.0.0-e2e --outdir "$WORK" >/dev/null

echo "=== Pulling $IMAGE ==="
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull --platform "$PLAT" "$IMAGE" >/dev/null

echo "=== Networks ==="
# Docker reserves .1 for the bridge gateway, so park it at .254 and use .1 for
# the router (its natural gateway address to the clients).
docker rm -f $ROUTER $ORIGIN $CLIENTS >/dev/null 2>&1 || true
docker network rm "$NET_WAN" "$NET_LAN" >/dev/null 2>&1 || true
docker network create --subnet "$WAN_SUBNET" --gateway "$WAN_GW" "$NET_WAN" >/dev/null
docker network create --internal --subnet "$LAN_SUBNET" --gateway "$LAN_GW" "$NET_LAN" >/dev/null

echo "=== Origin (HTTP + UDP echo on the WAN) ==="
docker run -d "${NO_PROXY_ENV[@]}" --name "$ORIGIN" --network "$NET_WAN" --ip "$ORIGIN_IP" alpine:3.20 sleep infinity >/dev/null
# socat serves both protocols; failure to prepare either is a test failure.
docker exec "${PACKAGE_ENV[@]}" "$ORIGIN" sh -ec 'apk add -q --no-cache socat >/dev/null'
docker exec "$ORIGIN" sh -c 'cat > /resp.sh <<'\''EOF'\''
#!/bin/sh
printf "HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\npong-http"
EOF
chmod +x /resp.sh'
docker exec -d "$ORIGIN" socat TCP-LISTEN:80,reuseaddr,fork EXEC:/resp.sh
docker exec -d "$ORIGIN" socat -T10 "UDP-RECVFROM:$UDP_PORT,fork" EXEC:/bin/cat

echo "=== Router (OpenWrt) ==="
docker run -d "${NO_PROXY_ENV[@]}" --name "$ROUTER" --hostname router --platform "$PLAT" \
    --network "$NET_WAN" --ip "$ROUTER_WAN" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN --tmpfs /tmp \
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
	option gateway "'"$WAN_GW"'"
	list dns "127.0.0.11"
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
docker exec -i "$ROUTER" sh -c 'cat > /tmp/ipk/meow.ipk' < "$WORK/meow_0.0.0-e2e_${OW_ARCH}.ipk"
docker exec -i "$ROUTER" sh -c 'cat > /tmp/ipk/luci.ipk' < "$WORK/luci-app-meow_0.0.0-e2e_all.ipk"
# Install both packages via opkg, including LuCI dependencies and postinst.
# Containers use their host kernel, so kernel-module packages cannot be
# installed here. nftables userspace and the actual rule probe cover that gap.
docker exec "${PACKAGE_ENV[@]}" "$ROUTER" sh -ec '
mkdir -p /var/lock
opkg update
opkg install luci-base nftables ip-full
opkg install /tmp/ipk/meow.ipk
opkg install /tmp/ipk/luci.ipk
' >"$WORK/opkg.log" 2>&1 || { cat "$WORK/opkg.log"; exit 1; }

# Probe capabilities in the router namespace (also works with Docker Desktop).
rexec 'set -e
nft add table inet meow_probe
nft "add chain inet meow_probe pre { type filter hook prerouting priority mangle; }"
nft add rule inet meow_probe pre meta l4proto udp tproxy to :7893
nft delete table inet meow_probe
' || skip "Docker host kernel lacks nftables TPROXY support"

for path in /usr/bin/meow /etc/init.d/meow /etc/config/meow /etc/meow/config.yaml /etc/rc.d/S95meow /www/luci-static/resources/view/meow/panel.js /www/luci-static/resources/view/meow/settings.js; do
    check "package installs $path" "INSTALLED" rexec "test -e $path && echo INSTALLED"
done
check "shipped config validates" "VALID" rexec '/usr/bin/meow -d /etc/meow -f /etc/meow/config.yaml -t && echo VALID'

echo "=== Enable meow + transparent proxy (tproxy) ==="
rexec '
set -e
uci set meow.main.enabled=1
uci set meow.tproxy.enabled=1
uci set meow.tproxy.mode=tproxy
uci set meow.tproxy.interface=lan
uci commit meow
/etc/init.d/meow restart
'
# gateway.sh loads once meow has bound the listener.
rexec '/usr/share/meow/gateway.sh wait && /usr/share/meow/gateway.sh up' >/dev/null 2>&1
sleep 2

echo "=== Clients (LAN-only; routed through the router) ==="
i=1
for c in $CLIENTS; do
    # Install iproute2 before isolating the client on the LAN (ARP cache tests).
    docker run -d "${NO_PROXY_ENV[@]}" --name "$c" --network "$NET_WAN" \
        --cap-add NET_ADMIN alpine:3.20 sleep infinity >/dev/null
    docker exec "${PACKAGE_ENV[@]}" "$c" apk --timeout 30 add -q --no-cache iproute2
    docker network disconnect "$NET_WAN" "$c"
    docker network connect --ip "10.13.37.1$i" "$NET_LAN" "$c"
    docker exec "$c" sh -c "ip route replace default via $ROUTER_LAN; printf 'nameserver %s\n' $ROUTER_LAN > /etc/resolv.conf"
    i=$((i + 1))
done
C1="$PFX-c1"; C2="$PFX-c2"

echo ""
echo "=== Assertions ==="

# Router service + control plane
check "procd service running"      "MEOW_UP"    bash -c "docker exec $ROUTER sh -c 'pidof meow >/dev/null && echo MEOW_UP'"
check "REST API /version"          "version"    rexec '/usr/libexec/meow-api GET /version'
check "built-in panel /ui"         "meow-rs"    rexec 'uclient-fetch -q -O - http://127.0.0.1:9090/ui'
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

# UDP is mandatory: no successful run may silently omit it.
check "client1 UDP via tproxy" "ping-udp" bash -c "docker exec $C1 sh -c 'echo ping-udp | nc -u -w2 $ORIGIN_IP $UDP_PORT'"
check "meow logged client UDP flow" "$ORIGIN_IP:$UDP_PORT" bash -c "docker exec $ROUTER logread -e meow | sed 's/\\x1b\\[[0-9;]*m//g'"
check "mixed-port HTTP proxy relay" "pong-http" docker exec "$C1" sh -c "printf 'GET http://$ORIGIN_IP/probe HTTP/1.1\\r\\nHost: $ORIGIN_IP\\r\\nConnection: close\\r\\n\\r\\n' | nc -w 10 $ROUTER_LAN 7890"

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

check "random install secret" "SECRET_OK" rexec 'secret=$(uci -q get meow.main.secret); [ "${#secret}" -eq 64 ] && echo SECRET_OK'
check "unauthenticated API rejected" "401" rexec 'curl --noproxy "*" -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9090/configs'

# Authenticated LuCI API bridge works without cross-origin browser HTTP.
check "LuCI API bridge installed executable" "EXECUTABLE" rexec 'test -x /usr/libexec/meow-api && echo EXECUTABLE'
check "LuCI API bridge GET" "version" rexec '/usr/libexec/meow-api GET /version'
check "LuCI RPC grants API bridge" "/usr/libexec/meow-api GET /version" bash -c "docker exec $ROUTER sh -c '$LOGIN'"
check "LuCI bridge rejects arbitrary destinations" "REJECTED" rexec 'if /usr/libexec/meow-api GET http://example.com >/dev/null 2>&1; then exit 1; else echo REJECTED; fi'
rexec "/usr/libexec/meow-api PATCH /configs '{\"mode\":\"direct\"}'"
check "LuCI API bridge changes mode" '"mode":"direct"' rexec '/usr/libexec/meow-api GET /configs'
rexec "/usr/libexec/meow-api PATCH /configs '{\"mode\":\"rule\"}'"
rexec 'uci set meow.main.secret=container-test-secret; uci commit meow; /etc/init.d/meow restart'
check "LuCI API bridge uses configured secret" "version" rexec '/usr/libexec/meow-api GET /version'
rexec 'uci set meow.main.secret=""; uci commit meow; /etc/init.d/meow restart'
check "empty secret restricts API to loopback" "LOOPBACK_ONLY" docker exec "$C1" sh -c "if wget -q -T 2 -O /dev/null http://$ROUTER_LAN:9090/configs; then exit 1; else echo LOOPBACK_ONLY; fi"

# Both Ethernet and ARP targets must be the selected MAC, never broadcast.
CLIENT_MAC=$(docker exec "$C1" cat /sys/class/net/eth0/address)
ROUTER_MAC=$(rexec 'cat /sys/class/net/eth1/address')
for c in $CLIENTS; do
    docker exec "$c" ip neigh replace "$LAN_GW" lladdr 02:00:00:00:00:fe nud reachable dev eth0
done
sleep 2
rexec "uci set meow.arp.gateway=$LAN_GW; uci add_list meow.arp.client=$CLIENT_MAC; uci commit meow; /usr/share/meow/arp-hijack.sh once"
check "selected client receives unicast ARP" "$ROUTER_MAC" docker exec "$C1" ip neigh show "$LAN_GW"
check "unselected client keeps gateway MAC" "02:00:00:00:00:fe" docker exec "$C2" ip neigh show "$LAN_GW"
rexec 'uci set meow.arp.interval=bad; uci commit meow'
check "ARP interval rejected" "REJECTED" rexec 'if /usr/share/meow/arp-hijack.sh once; then exit 1; else echo REJECTED; fi'
rexec 'uci set meow.arp.interval=2; uci commit meow'
rexec 'uci set meow.tproxy.ipv6=1; uci commit meow'
check "raw UCI IPv6 tproxy rejected" "REJECTED" rexec 'if /usr/share/meow/gateway.sh up; then exit 1; else echo REJECTED; fi'
rexec 'uci set meow.tproxy.ipv6=0; uci set meow.tproxy.tproxy_port="7893; flush ruleset"; uci commit meow'
check "raw UCI port injection rejected" "REJECTED" rexec 'if /usr/share/meow/gateway.sh up; then exit 1; else echo REJECTED; fi'
rexec 'uci set meow.tproxy.tproxy_port=7893; uci commit meow'
check "invalid settings preserve active rules" "meow_gateway" rexec 'nft list table inet meow_gateway'
docker exec -i "$ROUTER" sh -c 'cat > /tmp/delegated-luci.sh' < "$SCRIPT_DIR/openwrt-docker/delegated-luci.sh"
check "delegated LuCI transports and validation policy" "DELEGATED_OK" rexec 'sh /tmp/delegated-luci.sh'
# Stop while the managed gateway instance is still waiting for a missing port.
rexec 'uci set meow.tproxy.tproxy_port=65001; uci commit meow; /etc/init.d/meow restart'
sleep 1
rexec '/etc/init.d/meow stop'
sleep 32
check "stopped gateway cannot resurrect rules" "CLEAN" rexec '! nft list table inet meow_gateway >/dev/null 2>&1 && ! ip rule | grep -q "lookup 233" && echo CLEAN'
rexec 'uci set meow.tproxy.tproxy_port=7893; uci commit meow'

# Preserve the old packaging suite's lifecycle coverage and prove restart.
rexec '/etc/init.d/meow stop'
for _ in $(seq 1 20); do
    rexec 'pidof meow' >/dev/null 2>&1 || break
    sleep 1
done
check "service stop" "STOPPED" rexec '! pidof meow >/dev/null && echo STOPPED'
check "gateway teardown" "CLEAN" rexec '! nft list table inet meow_gateway >/dev/null 2>&1 && echo CLEAN'
rexec '/etc/init.d/meow start'
for _ in $(seq 1 30); do
    rexec '/usr/libexec/meow-api GET /version' >/dev/null 2>&1 && break
    sleep 1
done
check "service restart" "version" rexec '/usr/libexec/meow-api GET /version'

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
