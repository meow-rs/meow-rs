#!/bin/sh
# Transparent-proxy rules for traffic forwarded through this router
# (gateway or side-router mode). meow's built-in `inet meow_tproxy` table only
# covers the router's own output traffic; this adds `inet meow_gateway`, which
# hooks prerouting on the LAN device. See docs/tproxy-gateway.md.
#
# Modes (`option mode`):
#   tproxy    REDIRECT for TCP + kernel TPROXY for UDP (default). meow's TCP
#             listener recovers the original destination via SO_ORIGINAL_DST,
#             which only nat REDIRECT populates, so TCP is never sent through
#             kernel TPROXY; UDP has a real IP_TRANSPARENT listener.
#   redirect  nat REDIRECT, TCP only
#
# Usage: gateway.sh up|down|wait|status
# Settings come from the `tproxy` section of /etc/config/meow.

. /lib/functions.sh
. /lib/functions/network.sh

TABLE="inet meow_gateway"
RULES=/var/run/meow/gateway.nft
# Two marks, deliberately different (see docs/tproxy-gateway.md):
#   FWMARK       tags the UDP datagrams the mangle chain hands to the TPROXY
#                listener; a policy route delivers those marked packets
#                locally. TCP never uses it.
#   ROUTING_MARK meow's own outbound sockets carry this (SO_MARK, from the
#                YAML `routing-mark`), so both capture chains RETURN on it and
#                meow's own traffic is never re-proxied into a loop. This MUST
#                equal `routing-mark` in the meow YAML config (default 9527).
FWMARK=0x2333
ROUTING_MARK=0x2537
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

validate_config() {
    case "$mode:$ipv6" in redirect:0|redirect:1|tproxy:0) ;; *)
        logger -t meow 'gateway: invalid mode/IPv6 combination; IPv6 requires redirect mode'; return 1 ;; esac
    for port in "$tproxy_port" "$dns_port"; do
        case "$port" in ''|*[!0-9]*) return 1 ;; esac
        [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
    done
    case "$interface" in ''|*[!a-zA-Z0-9_.:-]*) return 1 ;; esac
    for cidr in $bypass; do
        case "$cidr" in *[!0-9a-fA-F.:/]*|'') return 1 ;; esac
    done
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

	# TCP goes through nat REDIRECT in BOTH modes (dstnat chain): meow's TCP
	# listener recovers the original destination with SO_ORIGINAL_DST, which
	# needs the conntrack DNAT that REDIRECT creates. Kernel TPROXY leaves no
	# conntrack entry, so a TPROXY'd TCP flow resolves to the listener's own
	# address and meow dials itself — a saturating loop. UDP has no REDIRECT
	# equivalent and a real IP_TRANSPARENT listener, so it uses TPROXY.
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
			meta mark $ROUTING_MARK return
	NFT
	[ "$dns_hijack" -eq 1 ] &&
		echo "		meta nfproto ipv4 meta l4proto udp th dport 53 redirect to :$dns_port"
	[ "$ipv6" -eq 1 ] || echo "		meta nfproto ipv6 return"
	cat <<-NFT
			fib daddr type local return
			ip daddr @reserved4 return
			ip6 daddr @reserved6 return
			meta l4proto tcp redirect to :$tproxy_port
		}
	NFT

	# redirect mode stops at TCP; tproxy mode adds the UDP TPROXY chain.
	if [ "$mode" != redirect ]; then
		cat <<-NFT

		chain mangle_tproxy {
			type filter hook prerouting priority mangle; policy accept;
			iifname != "$device" return
			meta mark $ROUTING_MARK return
		NFT
		[ "$dns_hijack" -eq 1 ] && echo "		meta l4proto udp th dport 53 return"
		[ "$ipv6" -eq 1 ] || echo "		meta nfproto ipv6 return"
		cat <<-NFT
			fib daddr type local return
			ip daddr @reserved4 return
			ip6 daddr @reserved6 return
			meta l4proto udp socket transparent 1 meta mark set $FWMARK accept
			meta l4proto udp tproxy to :$tproxy_port meta mark set $FWMARK accept
		}
		NFT
	fi

	echo "}"
}

route_up() {
	ip rule add fwmark $FWMARK lookup $ROUTE_TABLE || return 1
	ip route replace local 0.0.0.0/0 dev lo table $ROUTE_TABLE || return 1
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
    run)
        child=''
        trap '[ -z "$child" ] || kill "$child" 2>/dev/null; "$0" down; exit 0' TERM INT
        "$0" wait & child=$!
        wait "$child" || exit 1
        child=''
        "$0" up || exit 1
        while :; do sleep 3600 & child=$!; wait "$child"; done
        ;;
	up)
		load_config
		validate_config || { logger -t meow "gateway: invalid configuration"; exit 1; }
		network_get_device device "$interface"
		[ -n "$device" ] || {
			logger -t meow "gateway: no device for interface '$interface'"
			exit 1
		}
		case "$device" in *[!a-zA-Z0-9_.:-]*) exit 1 ;; esac
		mkdir -p "${RULES%/*}"
		gen_rules "$device" > "$RULES"
        if ! nft -c -f "$RULES"; then
            logger -t meow 'gateway: invalid rules or missing kernel support; install kmod-nft-socket kmod-nft-tproxy (opkg install, or apk add on newer OpenWrt)'
            exit 1
        fi
		nft delete table $TABLE 2>/dev/null
		route_down
		if ! nft -f "$RULES"; then
			logger -t meow "gateway: failed to load $RULES"
			exit 1
		fi
		if [ "$mode" = redirect ]; then
			logger -t meow "gateway: redirect $device tcp -> :$tproxy_port"
		else
			route_up || { "$0" down; logger -t meow "gateway: policy routing failed"; exit 1; }
			logger -t meow "gateway: tproxy $device tcp(redirect)+udp -> :$tproxy_port"
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
