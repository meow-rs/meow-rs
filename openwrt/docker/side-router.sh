#!/usr/bin/env bash
# Run OpenWrt in a Docker container attached to the physical LAN (macvlan in
# bridge mode) and configure it as a side router ("bypass router") running
# meow + luci-app-meow.
#
#   main router (DHCP, NAT)  ── LAN ──  clients
#            │                            │ gateway + DNS = OPENWRT_IP
#            └──── OpenWrt container (OPENWRT_IP, no DHCP, meow tproxy)
#
# Usage:
#   side-router.sh up [ipk-dir]   create network + container, provision it,
#                                 install *.ipk from ipk-dir (if given)
#   side-router.sh install <dir>  (re)install meow/luci-app-meow ipks
#   side-router.sh down           remove container, network and host shim
#   side-router.sh status
#
# Tunables (environment):
#   PARENT       host NIC on the LAN               (default: enP7s7)
#   SUBNET       LAN subnet                        (default: 192.168.0.0/24)
#   LAN_GW       main router address               (default: 192.168.0.1)
#   OPENWRT_IP   side-router address, unused, ideally outside the main
#                router's DHCP pool                (default: 192.168.0.250)
#   SHIM_IP      host-side macvlan address, lets this host reach the container
#                (macvlan children cannot talk to their parent directly)
#                                                  (default: 192.168.0.249)
#   IMAGE        OpenWrt rootfs image   (default: openwrt/rootfs:armsr-armv8-24.10.4)
#   NAME         container name                    (default: openwrt)

set -euo pipefail

PARENT=${PARENT:-enP7s7}
SUBNET=${SUBNET:-192.168.0.0/24}
LAN_GW=${LAN_GW:-192.168.0.1}
OPENWRT_IP=${OPENWRT_IP:-192.168.0.250}
SHIM_IP=${SHIM_IP:-192.168.0.249}
IMAGE=${IMAGE:-openwrt/rootfs:armsr-armv8-24.10.4}
NAME=${NAME:-openwrt}
NET=${NAME}-lan
SHIM=${NAME}-shim
PREFIX=${SUBNET#*/}

# Host kernel modules fw4 and meow's nftables rules need; containers cannot
# load modules themselves.
MODULES="nf_tables nft_chain_nat nft_nat nft_redir nft_masq nft_ct nft_fib
nft_fib_inet nft_fib_ipv4 nft_fib_ipv6 nft_reject nft_reject_inet
nft_reject_ipv4 nft_reject_ipv6 nft_limit nft_log nft_socket nft_tproxy
nf_nat nf_conntrack"

ow() { docker exec -i "$NAME" /bin/sh -s; }

host_modules() {
    local m loaded=()
    for m in $MODULES; do
        sudo modprobe "$m" 2>/dev/null && loaded+=("$m")
    done
    printf '%s\n' "${loaded[@]}" | sudo tee /etc/modules-load.d/openwrt-side-router.conf >/dev/null
}

host_shim() {
    ip link show "$SHIM" >/dev/null 2>&1 && return
    sudo ip link add "$SHIM" link "$PARENT" type macvlan mode bridge
    sudo ip addr add "$SHIM_IP/32" dev "$SHIM"
    sudo ip link set "$SHIM" up
    sudo ip route add "$OPENWRT_IP/32" dev "$SHIM"
}

create() {
    docker network inspect "$NET" >/dev/null 2>&1 ||
        docker network create -d macvlan \
            --subnet "$SUBNET" --gateway "$LAN_GW" \
            --aux-address "shim=$SHIM_IP" \
            -o parent="$PARENT" -o macvlan_mode=bridge "$NET"

    docker container inspect "$NAME" >/dev/null 2>&1 && return
    # procd needs SYS_ADMIN for its mounts; nftables needs NET_ADMIN.
    docker run -d --name "$NAME" --hostname "$NAME" \
        --platform linux/aarch64_generic \
        --network "$NET" --ip "$OPENWRT_IP" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --sysctl net.ipv4.ip_forward=1 \
        --sysctl net.ipv4.conf.all.send_redirects=0 \
        --sysctl net.ipv4.conf.default.send_redirects=0 \
        --sysctl net.ipv6.conf.all.disable_ipv6=1 \
        --restart unless-stopped \
        "$IMAGE" /sbin/init
}

provision() {
    # Wait for procd/ubus and for first-boot uci-defaults to finish, or they
    # overwrite the settings below.
    for _ in $(seq 1 60); do
        docker exec "$NAME" sh -c 'ubus call system board && [ -z "$(ls /etc/uci-defaults)" ]' \
            >/dev/null 2>&1 && break
        sleep 1
    done

    ow <<EOF
set -e
# LAN: static address on the existing LAN, main router as gateway + DNS.
cat > /etc/config/network <<'UCI'
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

config interface 'lan'
	option device 'eth0'
	option proto 'static'
	option ipaddr '$OPENWRT_IP'
	option netmask '$(ipcalc_mask "$PREFIX")'
	option gateway '$LAN_GW'
	list dns '$LAN_GW'
UCI

# Never serve DHCP / RA on a LAN that already has a router.
uci -q batch <<'UCI'
set dhcp.lan=dhcp
set dhcp.lan.interface='lan'
set dhcp.lan.ignore='1'
set dhcp.lan.dhcpv6='disabled'
set dhcp.lan.ra='disabled'
UCI
uci -q delete dhcp.wan || true
uci commit dhcp

# Side-router firewall: accept LAN, masquerade LAN->LAN forwarding so replies
# from the main router come back through us (symmetric conntrack).
i=0
while [ "\$(uci -q get firewall.@zone[\$i].name)" != lan ]; do i=\$((i + 1)); done
lan_zone="@zone[\$i]"
uci -q batch <<UCI
set firewall.\$lan_zone.input='ACCEPT'
set firewall.\$lan_zone.output='ACCEPT'
set firewall.\$lan_zone.forward='ACCEPT'
set firewall.\$lan_zone.masq='1'
set firewall.\$lan_zone.mtu_fix='1'
UCI
uci commit firewall

uci set system.@system[0].hostname='$NAME'
uci set system.@system[0].zonename='UTC'
uci commit system

# procd sandboxes some services (dnsmasq, ...) with ujail, which cannot
# pivot_root inside Docker. Replace it with a shim that runs the command
# after "--" unjailed; the container itself is the sandbox.
if ! grep -q side-router /sbin/ujail; then
	cat > /sbin/ujail <<'SHIM'
#!/bin/sh
# side-router.sh: ujail shim for containers
while [ \$# -gt 0 ] && [ "\$1" != "--" ]; do shift; done
[ "\$1" = "--" ] && shift
exec "\$@"
SHIM
	chmod 755 /sbin/ujail
fi

# On shutdown `umount -a -r` remounts / read-only, which sticks to the
# container's overlay across `docker restart`.
/etc/init.d/umount disable 2>/dev/null || true

/etc/init.d/odhcpd disable 2>/dev/null || true
/etc/init.d/odhcpd stop 2>/dev/null || true
# netifd occasionally fails to claim eth0 when restarted during boot.
for try in 1 2 3 4 5; do
	/etc/init.d/network restart
	sleep 3
	ifstatus lan | grep -q '"up": true' && break
done
/etc/init.d/dnsmasq restart
/etc/init.d/firewall restart
EOF

    # LuCI (uhttpd is already in the image).
    ow <<'EOF'
set -e
mkdir -p /var/lock
opkg list-installed | grep -q '^luci-base ' && exit 0
opkg update
opkg install luci luci-compat
EOF
}

# Dotted netmask for a prefix length (bash arithmetic, no ipcalc needed).
ipcalc_mask() {
    local p=$1 m=$(( 0xffffffff ^ ((1 << (32 - $1)) - 1) ))
    printf '%d.%d.%d.%d' $((m >> 24 & 255)) $((m >> 16 & 255)) $((m >> 8 & 255)) $((m & 255))
}

install_ipks() {
    local dir=$1 f
    docker exec "$NAME" rm -rf /tmp/ipk
    docker exec "$NAME" mkdir -p /tmp/ipk
    for f in "$dir"/meow_*.ipk "$dir"/luci-app-meow_*.ipk; do
        [ -f "$f" ] && docker cp "$f" "$NAME:/tmp/ipk/"
    done
    ow <<'EOF'
set -e
mkdir -p /var/lock
opkg install --force-reinstall /tmp/ipk/meow_*.ipk
[ -n "$(ls /tmp/ipk/luci-app-meow_*.ipk 2>/dev/null)" ] &&
	opkg install --force-reinstall /tmp/ipk/luci-app-meow_*.ipk
rm -rf /tmp/ipk /tmp/luci-*
/etc/init.d/rpcd restart
EOF
}

case "${1:-}" in
    up)
        host_modules
        create
        host_shim
        provision
        [ -n "${2:-}" ] && install_ipks "$2"
        echo "OpenWrt side router: http://$OPENWRT_IP/  (LuCI, user root)"
        ;;
    install)
        [ -n "${2:-}" ] || { echo "usage: $0 install <ipk-dir>" >&2; exit 1; }
        install_ipks "$2"
        ;;
    down)
        docker rm -f "$NAME" 2>/dev/null || true
        docker network rm "$NET" 2>/dev/null || true
        sudo ip link del "$SHIM" 2>/dev/null || true
        ;;
    status)
        docker ps --filter "name=^${NAME}$"
        docker exec "$NAME" sh -c 'ip -4 addr show eth0; ip route; /etc/init.d/meow status; nft list tables'
        ;;
    *)
        sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
        exit 1
        ;;
esac
