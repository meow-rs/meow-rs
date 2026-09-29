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

var MODE_HELP = {
	rule: _('Traffic follows your rules (recommended).'),
	global: _('All traffic goes through the proxy selected in the GLOBAL group.'),
	direct: _('All traffic bypasses the proxies.')
};

var COLORS = { ok: '#2e7d32', warn: '#ef6c00', bad: '#c62828' };

function badge(kind, text) {
	return E('span', {
		'class': 'label',
		'style': 'color: #fff; padding: 2px 8px; border-radius: 3px; background: ' + COLORS[kind]
	}, text);
}

function row(label, value) {
	return E('tr', { 'class': 'tr' }, [
		E('td', { 'class': 'td left', 'width': '33%' }, label),
		E('td', { 'class': 'td left' }, value)
	]);
}

function tabLink(tab, text) {
	return E('a', { 'href': L.url('admin/services/meow', tab) }, text);
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

	// First-run and failure guidance above the status table.
	renderBanner: function(enabled, running) {
		if (running)
			return '';
		if (!enabled)
			return E('div', { 'class': 'alert-message notice' }, [
				E('strong', {}, _('meow is not enabled.')), ' ',
				_('Add your proxies in the Configuration tab (or import a subscription in the Panel), then enable the service. '),
				E('button', {
					'class': 'cbi-button cbi-button-positive',
					'click': ui.createHandlerFn(this, 'handleEnable')
				}, _('Enable and start'))
			]);
		return E('div', { 'class': 'alert-message warning' }, [
			E('strong', {}, _('meow is stopped.')), ' ',
			_('If you did not stop it, the configuration probably failed to load; the reason is in the '),
			tabLink('log', _('Log')), '.'
		]);
	},

	refresh: function(nodes) {
		var self = this;
		var enabled = uci.get('meow', 'main', 'enabled') === '1';

		return Promise.all([
			meow.serviceRunning(),
			L.resolveDefault(meow.api('GET', '/version'), null),
			L.resolveDefault(meow.api('GET', '/configs'), null),
			L.resolveDefault(meow.api('GET', '/connections'), null),
			this.gatewayActive()
		]).then(function(r) {
			var running = r[0], version = r[1], cfg = r[2], conns = r[3],
			    gateway = r[4], now = Date.now();

			dom.content(nodes.banner, self.renderBanner(enabled, running));
			dom.content(nodes.service, running
				? [ badge('ok', _('Running')), ' ', version ? 'v' + String(version.version).replace(/^v/, '') : '' ]
				: badge(enabled ? 'bad' : 'warn', enabled ? _('Not running') : _('Disabled')));

			var tproxy = uci.get('meow', 'tproxy', 'enabled') === '1';
			dom.content(nodes.gateway, tproxy
				? (gateway
					? badge('ok', _('Active'))
					: [ badge('warn', _('Waiting')), ' ',
						E('small', {}, _('Rules load once meow is listening.')) ])
				: [ E('em', {}, _('Off')), ' — ', tabLink('settings', _('enable in Settings')) ]);

			var mode = cfg && cfg.mode;
			nodes.modeButtons.forEach(function(btn) {
				var active = mode === btn.getAttribute('data-mode');
				btn.classList.toggle('cbi-button-positive', active);
				btn.disabled = !cfg;
			});
			dom.content(nodes.modeHelp, MODE_HELP[mode] || (running ? '' : _('Available while meow is running.')));

			nodes.actions.start.style.display = running ? 'none' : '';
			nodes.actions.stop.style.display = running ? '' : 'none';
			nodes.actions.restart.style.display = running ? '' : 'none';

			if (conns) {
				var up = conns.uploadTotal || 0, down = conns.downloadTotal || 0;
				if (self.last) {
					var dt = (now - self.last.t) / 1000;
					dom.content(nodes.rate, '↑ %s/s   ↓ %s/s'.format(
						meow.formatBytes(Math.max(0, up - self.last.up) / dt),
						meow.formatBytes(Math.max(0, down - self.last.down) / dt)));
				}
				self.last = { t: now, up: up, down: down };
				dom.content(nodes.totals, '↑ %s   ↓ %s'.format(meow.formatBytes(up), meow.formatBytes(down)));
				dom.content(nodes.conns, String((conns.connections || []).length));
			} else {
				self.last = null;
				dom.content(nodes.rate, '-');
				dom.content(nodes.totals, '-');
				dom.content(nodes.conns, '-');
			}
		});
	},

	handleMode: function(mode) {
		return meow.api('PATCH', '/configs', { mode: mode }).then(L.bind(function() {
			return this.refresh(this.nodes);
		}, this)).catch(function(e) {
			ui.addNotification(null, E('p', _('Failed to switch mode: %s').format(e.message)), 'error');
		});
	},

	// Runs an init action, then waits briefly for procd to settle and reports
	// the resulting state instead of assuming success.
	service: function(action) {
		var self = this;
		var want = action !== 'stop';
		return fs.exec('/etc/init.d/meow', [ action ]).then(function(res) {
			if (res.code !== 0)
				throw new Error(res.stderr || _('Command failed'));
			return new Promise(function(resolve) { setTimeout(resolve, 1500); });
		}).then(function() {
			return meow.serviceRunning();
		}).then(function(running) {
			if (running !== want)
				throw new Error(want ? _('meow did not start; see the Log tab.') : _('meow is still running.'));
			ui.addTimeLimitedNotification(null, E('p', {
				start: _('meow started.'), stop: _('meow stopped.'), restart: _('meow restarted.')
			}[action]), 3000, 'info');
		}).catch(function(e) {
			ui.addNotification(null, E('p', e.message), 'error');
		}).then(function() {
			return self.refresh(self.nodes);
		});
	},

	handleStart: function() { return this.service('start'); },
	handleStop: function() { return this.service('stop'); },
	handleRestart: function() { return this.service('restart'); },

	handleEnable: function() {
		var self = this;
		uci.set('meow', 'main', 'enabled', '1');
		return uci.save()
			.then(function() { return uci.apply(); })
			.then(function() { return self.service('start'); })
			.catch(function(e) {
				ui.addNotification(null, E('p', _('Failed to enable: %s').format(e.message)), 'error');
			});
	},

	render: function() {
		var self = this;
		function action(name, cls, text) {
			return E('button', {
				'class': 'cbi-button ' + cls,
				'style': 'display: none;',
				'click': ui.createHandlerFn(self, name)
			}, text);
		}
		var nodes = this.nodes = {
			banner: E('div'),
			service: E('span', {}, _('Collecting data…')),
			gateway: E('span', {}, '-'),
			modeHelp: E('div', { 'style': 'margin-top: .4em; color: #888;' }),
			rate: E('span', {}, '-'),
			totals: E('span', {}, '-'),
			conns: E('span', {}, '-'),
			modeButtons: MODES.map(function(mode) {
				return E('button', {
					'class': 'cbi-button',
					'data-mode': mode,
					'disabled': true,
					'click': ui.createHandlerFn(self, 'handleMode', mode)
				}, mode.charAt(0).toUpperCase() + mode.slice(1));
			}),
			actions: {
				start: action('handleStart', 'cbi-button-positive', _('Start')),
				stop: action('handleStop', 'cbi-button-negative', _('Stop')),
				restart: action('handleRestart', 'cbi-button-apply', _('Restart'))
			}
		};

		poll.add(function() { return self.refresh(nodes); }, 3);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow')),
			E('div', { 'class': 'cbi-map-descr' },
				_('Rule-based proxy, compatible with mihomo (Clash Meta) configurations. ' +
				  'Pick proxies, manage subscriptions and inspect connections in the Panel tab.')),
			nodes.banner,
			E('div', { 'class': 'cbi-section' }, [
				E('table', { 'class': 'table' }, [
					row(_('Service'), nodes.service),
					row(_('Transparent proxy'), nodes.gateway),
					row(_('Proxy mode'), E('div', {}, [
						E('div', { 'class': 'cbi-page-actions', 'style': 'text-align: left; padding: 0;' },
							nodes.modeButtons),
						nodes.modeHelp
					])),
					row(_('Current speed'), nodes.rate),
					row(_('Total traffic'), nodes.totals),
					row(_('Active connections'), nodes.conns)
				])
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				// Without a secret the API is loopback-only; the Panel tab explains
				// that and offers to set one.
				meow.secret()
					? E('a', {
						'class': 'cbi-button cbi-button-action',
						'href': meow.panelURL(),
						'target': '_blank',
						'rel': 'noopener'
					}, _('Open panel'))
					: E('a', {
						'class': 'cbi-button cbi-button-action',
						'href': L.url('admin/services/meow/panel')
					}, _('Open panel')),
				' ', nodes.actions.start, ' ', nodes.actions.stop, ' ', nodes.actions.restart
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
