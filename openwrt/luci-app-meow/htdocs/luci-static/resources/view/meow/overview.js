'use strict';
'require view';
'require dom';
'require fs';
'require poll';
'require ui';
'require uci';
'require tools.meow as meow';

// Status page: service state from procd, everything else from the meow REST
// API (/version, /configs, /connections). Proxy selection, rules, groups and
// subscriptions live in the built-in panel (Panel tab).

var MODES = [ 'rule', 'global', 'direct' ];

function badge(ok, yes, no) {
	return E('span', {
		'class': 'label',
		'style': 'color: #fff; background: ' + (ok ? '#2e7d32' : '#c62828')
	}, ok ? yes : no);
}

function row(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'width': '33%' }, label),
		E('td', { 'class': 'td left' }, value)
	]);
}

return view.extend({
	load: function() {
		return uci.load('meow');
	},

	gatewayActive: function() {
		return fs.exec('/usr/share/meow/gateway.sh', [ 'status' ])
			.then(function(res) { return res.code === 0; })
			.catch(function() { return false; });
	},

	refresh: function(nodes) {
		var self = this;

		return Promise.all([
			meow.serviceRunning(),
			L.resolveDefault(meow.api('GET', '/version'), null),
			L.resolveDefault(meow.api('GET', '/configs'), null),
			L.resolveDefault(meow.api('GET', '/connections'), null),
			this.gatewayActive()
		]).then(function(r) {
			var running = r[0], version = r[1], cfg = r[2], conns = r[3],
			    gateway = r[4], now = Date.now();

			dom.content(nodes.service, badge(running, _('RUNNING'), _('NOT RUNNING')));
			dom.content(nodes.api, version
				? [ badge(true, _('Reachable'), ''), ' ', version.version ]
				: badge(false, '', _('Unreachable')));
			dom.content(nodes.gateway, uci.get('meow', 'tproxy', 'enabled') === '1'
				? badge(gateway, _('Active'), _('Enabled, rules not loaded'))
				: E('em', {}, _('Disabled')));

			nodes.modeButtons.forEach(function(btn) {
				var active = cfg && cfg.mode === btn.getAttribute('data-mode');
				btn.classList.toggle('cbi-button-positive', active);
				btn.disabled = !cfg;
			});

			if (conns) {
				var up = conns.uploadTotal || 0, down = conns.downloadTotal || 0;
				var rate = '';
				if (self.last) {
					var dt = (now - self.last.t) / 1000;
					rate = ' (↑ %s/s, ↓ %s/s)'.format(
						meow.formatBytes(Math.max(0, up - self.last.up) / dt),
						meow.formatBytes(Math.max(0, down - self.last.down) / dt));
				}
				self.last = { t: now, up: up, down: down };
				dom.content(nodes.traffic, '↑ %s ↓ %s%s'.format(
					meow.formatBytes(up), meow.formatBytes(down), rate));
				dom.content(nodes.conns, String((conns.connections || []).length));
			} else {
				self.last = null;
				dom.content(nodes.traffic, '-');
				dom.content(nodes.conns, '-');
			}
		});
	},

	handleMode: function(mode) {
		return meow.api('PATCH', '/configs', { mode: mode }).then(L.bind(function() {
			return this.refresh(this.nodes);
		}, this)).catch(function(e) {
			ui.addNotification(null, E('p', _('Failed to switch mode: %s').format(e.message)));
		});
	},

	handleRestart: function() {
		return fs.exec('/etc/init.d/meow', [ 'restart' ]).then(function() {
			ui.addTimeLimitedNotification(null, E('p', _('meow restarted')), 3000);
		});
	},

	render: function() {
		var self = this;
		var nodes = this.nodes = {
			service: E('span', {}, _('Collecting data…')),
			api: E('span', {}, '-'),
			gateway: E('span', {}, '-'),
			traffic: E('span', {}, '-'),
			conns: E('span', {}, '-'),
			modeButtons: MODES.map(function(mode) {
				return E('button', {
					'class': 'cbi-button',
					'data-mode': mode,
					'disabled': true,
					'click': ui.createHandlerFn(self, 'handleMode', mode)
				}, mode.charAt(0).toUpperCase() + mode.slice(1));
			})
		};

		poll.add(function() { return self.refresh(nodes); }, 3);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Rule-based tunneling proxy kernel, compatible with mihomo (Clash Meta). ' +
				  'Use the Panel tab for proxy selection, subscriptions, groups and rules.')),
			E('div', { 'class': 'cbi-section' }, [
				E('table', { 'class': 'table' }, [
					row(_('Service'), nodes.service),
					row(_('REST API'), nodes.api),
					row(_('Transparent proxy'), nodes.gateway),
					row(_('Mode'), E('div', { 'class': 'cbi-page-actions', 'style': 'text-align: left; padding: 0;' },
						nodes.modeButtons)),
					row(_('Traffic'), nodes.traffic),
					row(_('Active connections'), nodes.conns)
				])
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('a', {
					'class': 'cbi-button cbi-button-action',
					'href': meow.panelURL(),
					'target': '_blank',
					'rel': 'noopener'
				}, _('Open panel')),
				' ',
				E('button', {
					'class': 'cbi-button cbi-button-apply',
					'click': ui.createHandlerFn(this, 'handleRestart')
				}, _('Restart service'))
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
