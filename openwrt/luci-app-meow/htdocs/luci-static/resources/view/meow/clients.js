'use strict';
'require view';
'require fs';
'require network';
'require rpc';
'require uci';
'require ui';

// LAN clients known to this router. The main control is a per-client proxy
// bypass: ticked MACs are stored as `tproxy.bypass_mac` in /etc/config/meow and
// gateway.sh returns their traffic before both the proxy capture and the DNS
// hijack. ARP-based client steering (ARP spoofing, `arp.client`, enforced by
// the meow-arp service) is an opt-in advanced section; its Steer column is only
// shown while steering is enabled.

// MAC -> { name, ipaddrs, ip6addrs }: DHCP leases, static hosts, /etc/ethers
// and neighbours merged by LuCI, so side routers without DHCP still get rows.
var callHostHints = rpc.declare({
	object: 'luci-rpc',
	method: 'getHostHints',
	expect: { '': {} }
});

var callDHCPLeases = rpc.declare({
	object: 'luci-rpc',
	method: 'getDHCPLeases',
	expect: { '': {} }
});

function macList(section, option) {
	var l = uci.get('meow', section, option);
	if (l == null) return [];
	return (Array.isArray(l) ? l : [ l ]).map(function(m) { return m.toLowerCase(); });
}

// MACs of static leases (`config host` in /etc/config/dhcp). `mac` may be a
// list or a space-separated string of several MACs.
function staticMacs() {
	var out = {};
	uci.sections('dhcp', 'host', function(s) {
		var m = s.mac;
		(Array.isArray(m) ? m : String(m || '').split(/\s+/)).forEach(function(x) {
			if (x) out[x.toLowerCase()] = true;
		});
	});
	return out;
}

function ip4ToInt(ip) {
	var p = String(ip).split('.');
	if (p.length !== 4) return null;
	return ((+p[0] << 24) | (+p[1] << 16) | (+p[2] << 8) | +p[3]) >>> 0;
}

// ['192.168.1.1/24', ...] -> [{ net, mask }] for the proxied LAN interface.
function parseSubnets(cidrs) {
	return (cidrs || []).map(function(c) {
		var parts = String(c).split('/'), ip = ip4ToInt(parts[0]);
		var bits = parts.length > 1 ? +parts[1] : 32;
		if (ip === null || !(bits >= 0 && bits <= 32)) return null;
		var mask = bits ? (0xffffffff << (32 - bits)) >>> 0 : 0;
		return { self: ip, net: (ip & mask) >>> 0, mask: mask };
	}).filter(Boolean);
}

function inSubnets(ip, subnets) {
	var n = ip4ToInt(ip);
	return n !== null && subnets.some(function(s) {
		return n !== s.self && ((n & s.mask) >>> 0) === s.net;
	});
}

// IPv4 subnets of the interface transparent proxying listens on (tproxy.interface).
function lanSubnets() {
	var iface = uci.get('meow', 'tproxy', 'interface') || 'lan';
	return L.resolveDefault(network.getNetwork(iface), null).then(function(net) {
		return net ? net.getIPAddrs() : [];
	}).catch(function() { return []; });
}

return view.extend({
	load: function() {
		return uci.load('meow').then(function() {
			return Promise.all([
				null,
				uci.load('dhcp').catch(function() {}),
				L.resolveDefault(callHostHints(), {}),
				L.resolveDefault(callDHCPLeases(), {}),
				lanSubnets()
			]);
		});
	},

	// One row per LAN client, including selected MACs that are not currently
	// seen so they can still be released. Host hints also cover WAN-side
	// neighbours, the router itself, the all-zero MAC and IPv6-link-local-only
	// peers; a hint is kept only with an IPv4 on the LAN subnet other than the
	// router's own address (any IPv4 when the subnet is unknown). DHCP leases and selected MACs are always kept.
	buildClients: function(hints, leases, statics, bypass, steer, cidrs) {
		var byMac = {};
		var subnets = parseSubnets(cidrs);

		function row(mac) {
			return byMac[mac] || (byMac[mac] = {
				mac: mac, name: '', ip4: [], ip6: [], source: 'neighbour'
			});
		}

		Object.keys(hints || {}).forEach(function(m) {
			var h = hints[m] || {};
			var ip4 = (h.ipaddrs || h.ipv4 || []).filter(function(ip) {
				return ip && (!subnets.length || inSubnets(ip, subnets));
			});
			if (!ip4.length || /^(00:){5}00$/i.test(m)) return;
			var r = row(m.toLowerCase());
			r.name = h.name || '';
			r.ip4 = ip4;
			r.ip6 = (h.ip6addrs || h.ipv6 || []).slice();
		});

		((leases || {}).dhcp_leases || []).forEach(function(l) {
			if (!l.macaddr) return;
			var r = row(l.macaddr.toLowerCase());
			r.source = 'dhcp';
			if (!r.name && l.hostname && l.hostname !== '*') r.name = l.hostname;
			if (l.ipaddr && r.ip4.indexOf(l.ipaddr) === -1) r.ip4.unshift(l.ipaddr);
		});

		Object.keys(statics || {}).forEach(function(m) {
			if (byMac[m] && byMac[m].source !== 'dhcp') byMac[m].source = 'static';
		});

		bypass.concat(steer).forEach(function(m) {
			if (!byMac[m]) row(m).source = 'offline';
		});

		return Object.keys(byMac).map(function(m) { return byMac[m]; })
			.sort(function(a, b) {
				var ao = a.source === 'offline', bo = b.source === 'offline';
				if (ao !== bo) return ao ? 1 : -1;
				if (!a.name !== !b.name) return a.name ? -1 : 1;
				return a.name.localeCompare(b.name) ||
					(a.ip4[0] || '').localeCompare(b.ip4[0] || '', undefined, { numeric: true }) ||
					a.mac.localeCompare(b.mac);
			});
	},

	render: function(data) {
		var self = this;
		var statics = staticMacs();
		var bypass = macList('tproxy', 'bypass_mac');
		var steer = macList('arp', 'client');
		var arpEnabled = uci.get('meow', 'arp', 'enabled') === '1';
		var tproxyEnabled = uci.get('meow', 'tproxy', 'enabled') === '1';
		var clients = this.buildClients(data[2], data[3], statics, bypass, steer, data[4]);
		var hidden = 'display: none;';
		var sourceLabel = {
			dhcp: _('DHCP'), static: _('Static'), neighbour: _('Neighbour'), offline: _('Offline')
		};

		this.bypassChecks = {};
		this.steerChecks = {};
		// Steer cells and the DHCP-only empty state follow the ARP toggle.
		// Neighbour rows also stay visible when their current Bypass tick is set.
		this.arpOnly = [];
		this.dhcpOnly = [];
		this.neighbourRows = [];
		this.initial = { arpEnabled: arpEnabled, steer: steer.slice().sort().join(' ') };

		function arpOnly(node) { self.arpOnly.push(node); return node; }
		function steerCell(tag, content) {
			return arpOnly(E(tag, { 'class': tag === 'th' ? 'th' : 'td', 'style': arpEnabled ? '' : hidden }, content));
		}
		// Without ARP steering only DHCP clients (leases and static leases) are
		// listed; neighbour-only hosts stay visible when already bypassed.
		function dhcpVisible(c) {
			return c.source !== 'neighbour' || bypass.indexOf(c.mac) !== -1;
		}

		var rows = [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th', 'style': 'width: 4em;' }, _('Bypass')),
				steerCell('th', _('Steer')),
				E('th', { 'class': 'th' }, _('Hostname')),
				E('th', { 'class': 'th' }, _('IP address')),
				E('th', { 'class': 'th' }, _('MAC address')),
				E('th', { 'class': 'th' }, _('Source'))
			])
		];

		if (!clients.length) {
			rows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td', 'colspan': '6' },
					E('em', {}, _('No LAN clients known yet. DHCP leases and neighbours appear here once clients are active.')))
			]));
		} else if (!clients.some(dhcpVisible)) {
			rows.push(this.dhcpOnly[this.dhcpOnly.push(E('tr', { 'class': 'tr', 'style': arpEnabled ? hidden : '' }, [
				E('td', { 'class': 'td', 'colspan': '6' },
					E('em', {}, _('No DHCP clients. Enable ARP client steering below to list other LAN neighbours.')))
			])) - 1]);
		}

		clients.forEach(function(c) {
			// Bypass and Steer are exclusive: bypassing a steered client would
			// only route it through this router unproxied.
			var bp = E('input', {
				'type': 'checkbox',
				'checked': bypass.indexOf(c.mac) !== -1 ? '' : null,
				'change': function() { if (bp.checked) st.checked = false; }
			});
			var st = E('input', {
				'type': 'checkbox',
				'checked': steer.indexOf(c.mac) !== -1 ? '' : null,
				'change': function() { if (st.checked) bp.checked = false; }
			});
			self.bypassChecks[c.mac] = bp;
			self.steerChecks[c.mac] = st;

			var ips = [ E('span', {}, c.ip4.length ? c.ip4.join(', ') : '-') ];
			if (c.ip6.length)
				ips.push(E('br'), E('small', { 'style': 'color: #888;' }, c.ip6.join(', ')));

			var tr = E('tr', { 'class': 'tr', 'style': arpEnabled || dhcpVisible(c) ? '' : hidden }, [
				E('td', { 'class': 'td' }, bp),
				steerCell('td', st),
				E('td', { 'class': 'td' }, c.name || '-'),
				E('td', { 'class': 'td' }, ips),
				E('td', { 'class': 'td' }, c.mac),
				E('td', { 'class': 'td' }, sourceLabel[c.source])
			]);
			rows.push(tr);
			if (c.source === 'neighbour')
				self.neighbourRows.push({ node: tr, bypass: bp });
		});

		var intro = E('p', {}, [
			_('Tick a client to bypass the transparent proxy: its traffic (including DNS) ' +
			  'goes out directly. Clients are matched by MAC address, so a new DHCP ' +
			  'lease keeps the setting.'),
			tproxyEnabled ? '' : E('strong', {}, [ ' ',
				_('Transparent proxy is disabled (Settings), so no client is proxied right now.') ])
		]);

		this.arpToggle = E('input', {
			'type': 'checkbox',
			'id': 'arp-enabled',
			'checked': arpEnabled ? '' : null,
			'change': function(ev) { self.showSteer(ev.target.checked); }
		});

		var arp = E('details', { 'class': 'cbi-section', 'open': arpEnabled ? '' : null }, [
			E('summary', {}, E('strong', {}, _('ARP client steering (advanced)'))),
			E('div', { 'class': 'alert-message warning', 'style': 'margin: 1em 0;' }, [
				_('For the clients you tick in the Steer column, this router announces itself ' +
				  'as their gateway (ARP spoofing) so meow transparently proxies them without ' +
				  'touching the client or the main router. Only use it for devices you ' +
				  'administer on a network you control. Untick a client to release it. ' +
				  'Transparent proxy must be enabled (Settings) for steered traffic to be handled.')
			]),
			E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title', 'for': 'arp-enabled' }, _('Enable steering')),
				E('div', { 'class': 'cbi-value-field' }, [
					this.arpToggle,
					E('span', { 'style': 'margin-left: .5em; color: #888;' },
						_('Master switch. Shows the Steer column and non-DHCP LAN neighbours; when off, no client is steered.'))
				])
			])
		]);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow Clients')),
			intro,
			E('div', { 'class': 'cbi-section' }, [
				E('table', { 'class': 'table cbi-section-table' }, rows)
			]),
			// Saving uses LuCI's standard page footer (Save & Apply).
			E('div', { 'style': 'margin: .5em 0;' }, [
				E('button', {
					'class': 'cbi-button',
					'click': function() { location.reload(); }
				}, _('Reload list'))
			]),
			arp
		]);
	},

	showSteer: function(on) {
		this.arpOnly.forEach(function(n) { n.style.display = on ? '' : 'none'; });
		this.neighbourRows.forEach(function(row) {
			row.node.style.display = on || row.bypass.checked ? '' : 'none';
		});
		var hasBypass = this.neighbourRows.some(function(row) { return row.bypass.checked; });
		this.dhcpOnly.forEach(function(n) { n.style.display = on || hasBypass ? 'none' : ''; });
	},

	handleSaveApply: function() {
		var self = this;
		var arpEnabled = this.arpToggle.checked;
		function ticked(checks) {
			return Object.keys(checks).filter(function(m) { return checks[m].checked; });
		}
		var bypass = ticked(this.bypassChecks);
		// Hidden Steer ticks are kept, so disabling steering does not forget them.
		var steer = ticked(this.steerChecks).filter(function(m) { return bypass.indexOf(m) === -1; });
		var arpChanged = arpEnabled !== this.initial.arpEnabled ||
			steer.slice().sort().join(' ') !== this.initial.steer;

		if (bypass.length)
			uci.set('meow', 'tproxy', 'bypass_mac', bypass);
		else
			uci.unset('meow', 'tproxy', 'bypass_mac');

		uci.set('meow', 'arp', 'enabled', arpEnabled ? '1' : '0');
		if (steer.length)
			uci.set('meow', 'arp', 'client', steer);
		else
			uci.unset('meow', 'arp', 'client');

		return uci.save()
			.then(function() { return uci.apply(); })
			.then(function() {
				if (arpChanged)
					return fs.exec('/etc/init.d/meow-arp', [ 'restart' ]).catch(function() {});
			})
			.then(function() {
				ui.addTimeLimitedNotification(null, E('p', arpEnabled
					? _('Bypassing %d client(s); steering %d.').format(bypass.length, steer.length)
					: _('Bypassing %d client(s); steering disabled.').format(bypass.length)), 4000, 'info');
			})
			.catch(function(e) {
				ui.addNotification(null, E('p', _('Failed to apply: %s').format(e.message)));
			});
	},

	handleSave: null,
	handleReset: null
});
