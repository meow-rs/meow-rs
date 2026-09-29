#!/bin/sh
# ARP-based client steering for meow side-router / gateway mode.
#
# For the LAN clients you SELECT, this periodically sends unicast ARP replies
# claiming the network's real gateway IP is at this device's MAC. Those clients
# then send their off-LAN traffic here instead, so meow's transparent proxy
# handles them WITHOUT any per-client configuration and without changing the
# main router's DHCP.
#
# This is ARP spoofing. Use it only to steer devices you own or administer, on
# a network you control. It is OFF by default and touches only the MACs listed
# in the `arp_hijack` section of /etc/config/meow — never the whole LAN.
#
# A client is restored by simply de-selecting it (its ARP cache relearns the
# real gateway within its normal timeout once we stop announcing).
#
# Usage: arp-hijack.sh clients | run | once
# Settings come from the `arp_hijack` section of /etc/config/meow.

. /lib/functions.sh
. /lib/functions/network.sh

clients=""
add_client() { clients="$clients $1"; }

load_config() {
	config_load meow
	config_get_bool enabled arp enabled 0
	config_get interface arp interface lan
	config_get gateway arp gateway ''
	config_get interval arp interval 2
	config_list_foreach arp client add_client

	network_get_device device "$interface"
	[ -n "$gateway" ] || network_get_gateway gateway "$interface"
}

# JSON array of the LAN neighbour table, marking which MACs are selected.
cmd_clients() {
	load_config
	local sel
	sel=" $(echo "$clients" | tr 'A-F' 'a-f') "
	printf '['
	[ -n "$device" ] && ip neigh show dev "$device" 2>/dev/null | awk -v sel="$sel" '
		{
			ip=$1; mac=""; st=$NF
			for (i=1;i<=NF;i++) if ($i=="lladdr") mac=$(i+1)
			if (mac=="" || index(ip,":")) next
			lm=tolower(mac)
			s=(index(sel," " lm " ")?"true":"false")
			printf "%s{\"ip\":\"%s\",\"mac\":\"%s\",\"state\":\"%s\",\"selected\":%s}", (c++?",":""), ip, mac, st, s
		}'
	printf ']\n'
}

# Current IP for a selected MAC (resolved fresh each sweep; DHCP may move it).
mac_to_ip() {
	ip neigh show dev "$device" 2>/dev/null | awk -v m="$(echo "$1" | tr 'A-F' 'a-f')" '
		{ mac=""; for (i=1;i<=NF;i++) if ($i=="lladdr") mac=tolower($(i+1))
		  if (mac==m && !index($1,":")) { print $1; exit } }'
}

sweep() {
	local mac ip
	for mac in $clients; do
		ip=$(mac_to_ip "$mac")
		[ -n "$ip" ] || continue
		# ARP reply: "gateway is at <our MAC>", unicast to the client.
		if ! /usr/bin/meow arp-reply "$device" "$gateway" "$mac" "$ip"; then
            logger -t meow-arp "failed to send unicast reply to $mac ($ip)"
            return 1
        fi
	done
}

precheck() {
    case "$interval" in ''|*[!0-9]*) logger -t meow-arp 'interval must be an integer from 1 to 3600'; return 1 ;; esac
    [ "$interval" -ge 1 ] && [ "$interval" -le 3600 ] || return 1
	[ -n "$device" ] || { logger -t meow-arp "no device for interface '$interface'"; return 1; }
	[ -n "$gateway" ] || { logger -t meow-arp "no gateway for '$interface'; set arp.gateway"; return 1; }
	return 0
}

case "$1" in
	clients)
		cmd_clients
		;;
	once)
		load_config
		precheck || exit 1
		sweep
		;;
	run)
		load_config
		[ "$enabled" -eq 1 ] || { logger -t meow-arp "disabled; not steering"; exit 0; }
		precheck || exit 1
		[ -n "$clients" ] || { logger -t meow-arp "no clients selected; idle"; }
		logger -t meow-arp "steering [$clients ] via $device as gateway $gateway"
		while :; do
			sweep || exit 1
			sleep "$interval"
		done
		;;
	*)
		echo "usage: $0 clients|run|once" >&2
		exit 1
		;;
esac
