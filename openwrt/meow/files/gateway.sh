#!/bin/sh
# Transparent-proxy rules for traffic forwarded through this router
# (gateway or side-router mode). meow's built-in `inet meow_tproxy` table only
# covers the router's own output traffic; this adds `inet meow_gateway`, which
# hooks prerouting on the LAN device. See docs/tproxy-gateway.md.
#
# Modes (`option mode`):
#   tproxy    kernel TPROXY for TCP and UDP (default): a mangle-prerouting
#             `tproxy` rule hands packets to meow's transparent listener and
#             marks them; a policy route delivers marked packets locally
#   redirect  nat REDIRECT, TCP only
#
# Usage: gateway.sh up|down|wait|status
# Settings come from the `tproxy` section of /etc/config/meow.

. /lib/functions.sh
. /lib/functions/network.sh

TABLE="inet meow_gateway"
RULES=/var/run/meow/gateway.nft
# Policy routing for TPROXY-marked packets. Distinct from meow's
# `routing-mark` (9527 = 0x2537), which exempts its own DIRECT sockets.
FWMARK=0x2333
ROUTE_TABLE=233

load_config() {
	config_load meow
	config_get interface tproxy interface lan
	config_get mode tproxy mode tproxy
	config_get tproxy_port tproxy tproxy_port 7893
	config_get_bool dns_hijack tproxy dns_hijack 1
	config_get dns_port tproxy dns_port 1053
	config_get_bool ipv6 tproxy ipv6 0
	config_get bypass tproxy bypass ''
}

port_listening() {
	# /proc/net/tcp{,6} list local ports in hex; state 0A is LISTEN.
	local hex
	hex=$(printf '%04X' "$1")
	grep -qE "^ *[0-9]+: [0-9A-F]+:$hex [0-9A-F]+:[0-9A-F]+ 0A" \
		/proc/net/tcp /proc/net/tcp6 2>/dev/null
}

gen_rules() {
	local device="$1" extra4="" extra6="" cidr

	for cidr in $bypass; do
		case "$cidr" in
			*:*) extra6="$extra6, $cidr" ;;
			*) extra4="$extra4, $cidr" ;;
		esac
	done

	cat <<-NFT
	table inet meow_gateway {
		set reserved4 {
			type ipv4_addr; flags interval; auto-merge
			elements = {
				0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
				169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16,
				224.0.0.0/4, 240.0.0.0/4$extra4
			}
		}
		set reserved6 {
			type ipv6_addr; flags interval; auto-merge
			elements = { ::/128, ::1/128, fc00::/7, fe80::/10, ff00::/8$extra6 }
		}

		chain dstnat {
			type nat hook prerouting priority dstnat - 5; policy accept;
			iifname != "$device" return
	NFT
	[ "$dns_hijack" -eq 1 ] &&
		echo "		meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 redirect to :$dns_port"

	if [ "$mode" = redirect ]; then
		[ "$ipv6" -eq 1 ] || echo "		meta nfproto ipv6 return"
		cat <<-NFT
			fib daddr type local return
			ip daddr @reserved4 return
			ip6 daddr @reserved6 return
			meta l4proto tcp redirect to :$tproxy_port
		}
	}
		NFT
		return
	fi

	cat <<-NFT
		}

		chain mangle_tproxy {
			type filter hook prerouting priority mangle; policy accept;
			iifname != "$device" return
	NFT
	# DNS is hijacked by the dstnat chain above; keep it out of TPROXY.
	[ "$dns_hijack" -eq 1 ] && echo "		meta l4proto { tcp, udp } th dport 53 return"
	[ "$ipv6" -eq 1 ] || echo "		meta nfproto ipv6 return"
	cat <<-NFT
			fib daddr type local return
			ip daddr @reserved4 return
			ip6 daddr @reserved6 return
			meta l4proto tcp socket transparent 1 meta mark set $FWMARK accept
			meta l4proto { tcp, udp } tproxy to :$tproxy_port meta mark set $FWMARK accept
		}
	}
	NFT
}

route_up() {
	ip rule add fwmark $FWMARK lookup $ROUTE_TABLE
	ip route replace local 0.0.0.0/0 dev lo table $ROUTE_TABLE
	if [ "$ipv6" -eq 1 ]; then
		ip -6 rule add fwmark $FWMARK lookup $ROUTE_TABLE
		ip -6 route replace local ::/0 dev lo table $ROUTE_TABLE
	fi
}

route_down() {
	while ip rule del fwmark $FWMARK lookup $ROUTE_TABLE 2>/dev/null; do :; done
	ip route flush table $ROUTE_TABLE 2>/dev/null
	while ip -6 rule del fwmark $FWMARK lookup $ROUTE_TABLE 2>/dev/null; do :; done
	ip -6 route flush table $ROUTE_TABLE 2>/dev/null
	return 0
}

case "$1" in
	up)
		load_config
		network_get_device device "$interface"
		[ -n "$device" ] || {
			logger -t meow "gateway: no device for interface '$interface'"
			exit 1
		}
		mkdir -p "${RULES%/*}"
		gen_rules "$device" > "$RULES"
		nft delete table $TABLE 2>/dev/null
		route_down
		if ! nft -f "$RULES"; then
			logger -t meow "gateway: failed to load $RULES"
			exit 1
		fi
		if [ "$mode" = redirect ]; then
			logger -t meow "gateway: redirect $device tcp -> :$tproxy_port"
		else
			route_up
			logger -t meow "gateway: tproxy $device tcp+udp -> :$tproxy_port"
		fi
		;;
	down)
		nft delete table $TABLE 2>/dev/null
		route_down
		;;
	wait)
		# Block until meow binds the tproxy listener (30s cap, then load
		# anyway so the rules fail closed rather than leaking traffic).
		load_config
		i=0
		while [ $i -lt 150 ]; do
			port_listening "$tproxy_port" && exit 0
			sleep 0.2
			i=$((i + 1))
		done
		logger -t meow "gateway: :$tproxy_port not listening after 30s"
		exit 0
		;;
	status)
		nft list table $TABLE
		;;
	*)
		echo "usage: $0 up|down|wait|status" >&2
		exit 1
		;;
esac
