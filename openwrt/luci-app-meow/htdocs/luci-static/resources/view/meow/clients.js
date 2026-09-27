'use strict';
'require view';
'require fs';
'require uci';
'require ui';

// ARP-based client steering. For selected LAN clients, meow-arp announces this
// device as the gateway so their traffic is transparently proxied without
// per-client configuration. This is ARP spoofing — the page says so plainly.
// The list of steered clients is stored as `arp.client` MAC entries in
// /etc/config/meow; the meow-arp service enforces it.

// The neighbour table is read through the arp-hijack helper (it emits JSON).
function loadClients() {
	return fs.exec('/usr/share/meow/arp-hijack.sh', [ 'clients' ]).then(function(r) {
		try { return JSON.parse(r.stdout || '[]'); }
		catch (e) { return []; }
	}).catch(function() { return []; });
}

function selectedMacs() {
	var l = uci.get('meow', 'arp', 'client');
	if (l == null) return [];
	return (Array.isArray(l) ? l : [ l ]).map(function(m) { return m.toLowerCase(); });
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('meow'),
			loadClients()
		]);
	},

	render: function(data) {
		var self = this;
		var clients = data[1] || [];
		var enabled = uci.get('meow', 'arp', 'enabled') === '1';
		var sel = selectedMacs();
		this.checks = {};

		var warn = E('div', {
			'class': 'alert-message warning',
			'style': 'margin-bottom: 1em;'
		}, [
			E('strong', {}, _('ARP client steering.')), ' ',
			_('For the clients you tick below, this router announces itself as their ' +
			  'gateway (ARP spoofing) so meow transparently proxies them without touching ' +
			  'the client or the main router. Only use it for devices you administer on a ' +
			  'network you control. Untick a client to release it. Transparent proxy must ' +
			  'be enabled (Settings) for steered traffic to be handled.')
		]);

		var toggle = E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, _('Enable steering')),
			E('div', { 'class': 'cbi-value-field' }, [
				E('input', {
					'type': 'checkbox',
					'id': 'arp-enabled',
					'checked': enabled ? '' : null
				}),
				E('span', { 'style': 'margin-left: .5em; color: #888;' },
					_('Master switch. When off, no client is steered regardless of ticks.'))
			])
		]);

		var rows = [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th', 'style': 'width: 4em;' }, _('Steer')),
				E('th', { 'class': 'th' }, _('IP address')),
				E('th', { 'class': 'th' }, _('MAC address')),
				E('th', { 'class': 'th' }, _('State'))
			])
		];

		if (!clients.length) {
			rows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td', 'colspan': '4' },
					E('em', {}, _('No LAN neighbours discovered yet. Generate some traffic from the clients and reload.')))
			]));
		}

		clients.forEach(function(c) {
			var mac = (c.mac || '').toLowerCase();
			var cb = E('input', {
				'type': 'checkbox',
				'checked': sel.indexOf(mac) !== -1 ? '' : null
			});
			self.checks[mac] = cb;
			rows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, cb),
				E('td', { 'class': 'td' }, c.ip || '-'),
				E('td', { 'class': 'td' }, c.mac || '-'),
				E('td', { 'class': 'td' }, c.state || '-')
			]));
		});

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow Clients')),
			warn,
			toggle,
			E('div', { 'class': 'cbi-section' }, [
				E('table', { 'class': 'table cbi-section-table' }, rows)
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', {
					'class': 'cbi-button cbi-button-save',
					'click': ui.createHandlerFn(this, 'handleSaveApply')
				}, _('Save & Apply')),
				' ',
				E('button', {
					'class': 'cbi-button',
					'click': function() { location.reload(); }
				}, _('Reload list'))
			])
		]);
	},

	handleSaveApply: function() {
		var self = this;
		var enabled = document.getElementById('arp-enabled').checked;
		var macs = Object.keys(this.checks).filter(function(m) {
			return self.checks[m].checked;
		});

		uci.set('meow', 'arp', 'enabled', enabled ? '1' : '0');
		if (macs.length)
			uci.set('meow', 'arp', 'client', macs);
		else
			uci.unset('meow', 'arp', 'client');

		return uci.save()
			.then(function() { return uci.apply(); })
			.then(function() {
				return fs.exec('/etc/init.d/meow-arp', [ 'restart' ]).catch(function() {});
			})
			.then(function() {
				ui.addTimeLimitedNotification(null,
					E('p', enabled
						? _('Steering %d client(s).').format(macs.length)
						: _('Steering disabled.')), 4000, 'info');
			})
			.catch(function(e) {
				ui.addNotification(null, E('p', _('Failed to apply: %s').format(e.message)));
			});
	},

	handleSave: null,
	handleReset: null
});
