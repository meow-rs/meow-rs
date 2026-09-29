'use strict';
'require view';
'require form';
'require dom';
'require fs';
'require tools.meow_settings as settings';
'require poll';
'require uci';
'require tools.meow as meow';

function renderStatus(running) {
	return running
		? E('span', { 'style': 'color: #2e7d32; font-weight: bold;' },
			_('RUNNING'))
		: E('span', { 'style': 'color: #c62828; font-weight: bold;' },
			_('NOT RUNNING'));
}

return view.extend({
	load: function() {
		return Promise.all([ uci.load('meow'), uci.load('network') ]);
	},

	render: function() {
		var m, s, o;

		m = new form.Map('meow', _('meow'),
			_('Service and transparent-proxy settings. Saving also updates the YAML ' +
			  'configuration to match; Save & Apply restarts meow. Proxies, rules and ' +
			  'upstream DNS are edited in the Configuration tab.'));

		var save = m.save;
		m.save = function(callback, silent) {
			var rollback;
			return save.call(this, function() {
				return Promise.resolve().then(callback).then(function() {
					return settings.save();
				}).then(function(undo) { rollback = undo; });
			}, silent).catch(function(error) {
				return Promise.resolve(rollback && rollback()).then(function() { throw error; });
			});
		};

		s = m.section(form.NamedSection, 'main', 'meow', _('Service'));
		s.tab('basic', _('Basic'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('basic', form.DummyValue, '_status', _('Status'));
		o.rawhtml = true;
		o.cfgvalue = function() {
			var node = E('span', {}, _('Collecting data…'));
			poll.add(function() {
				return meow.serviceRunning().then(function(running) {
					dom.content(node, renderStatus(running));
				});
			});
			return node;
		};

		o = s.taboption('basic', form.Flag, 'enabled', _('Enable meow'),
			_('Start meow now and at every boot. Save & Apply restarts it.'));
		o.rmempty = false;

		o = s.taboption('basic', form.Value, 'panel_port', _('Web panel port'),
			_('Port of the built-in web panel and REST API (external-controller in the YAML).'));
		o.datatype = 'port';
		o.default = '9090';
		o.rmempty = false;

		o = s.taboption('basic', form.Value, 'secret', _('Panel password'),
			_('The API secret. Leave empty to allow the panel only from this router; ' +
			  'set it to open the panel from other LAN devices.'));
		o.password = true;

		o = s.taboption('advanced', form.Value, 'config_file', _('Configuration file'),
			_('Fixed path used by the managed service; edit it in the Configuration tab.'));
		o.default = '/etc/meow/config.yaml';
		o.readonly = true;
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'work_dir', _('Working directory'),
			_('GeoIP databases, caches and downloaded rule sets are kept here.'));
		o.default = '/etc/meow';
		o.readonly = true;
		o.rmempty = false;

		s = m.section(form.NamedSection, 'tproxy', 'transparent', _('Transparent proxy'),
			_('Proxy LAN devices without configuring each of them: devices that use this ' +
			  'router as their gateway (and DNS) are proxied automatically. Local and ' +
			  'private destinations are never proxied. Individual devices can be excluded ' +
			  'in the Clients tab. The YAML configuration is updated to match on save.'));
		s.addremove = false;
		s.tab('basic', _('Basic'));
		s.tab('advanced', _('Advanced'));

		o = s.taboption('basic', form.DummyValue, '_gateway', _('Status'));
		o.rawhtml = true;
		o.cfgvalue = function() {
			var node = E('span', {}, _('Collecting data…'));
			poll.add(function() {
				return fs.exec('/usr/share/meow/gateway.sh', [ 'status' ]).catch(function() {
					return { code: 1 };
				}).then(function(res) {
					dom.content(node, uci.get('meow', 'tproxy', 'enabled') !== '1'
						? E('em', {}, _('Off'))
						: res.code === 0
							? E('span', { 'style': 'color: #2e7d32; font-weight: bold;' }, _('Active'))
							: E('span', { 'style': 'color: #ef6c00; font-weight: bold;' },
								_('Not active — waiting for meow (check the Log tab if this persists)')));
				});
			});
			return node;
		};

		o = s.taboption('basic', form.Flag, 'enabled', _('Proxy LAN devices'));
		o.rmempty = false;

		o = s.taboption('basic', form.ListValue, 'mode', _('Traffic to proxy'));
		o.value('tproxy', _('TCP and UDP (recommended)'));
		o.value('redirect', _('TCP only (for kernels without TPROXY support)'));
		o.default = 'tproxy';

		o = s.taboption('basic', form.ListValue, 'interface', _('LAN interface'),
			_('Devices connected through this interface are proxied.'));
		uci.sections('network', 'interface', function(sec) {
			if (sec['.name'] !== 'loopback')
				o.value(sec['.name']);
		});
		o.default = 'lan';

		o = s.taboption('basic', form.Flag, 'dns_hijack', _('Handle LAN DNS'),
			_('Answer every DNS query from LAN devices with meow. Required for fake-ip mode.'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('advanced', form.Value, 'tproxy_port', _('Listener port'),
			_('Port of the transparent-proxy listener created in the YAML configuration.'));
		o.datatype = 'port';
		o.default = '7893';

		o = s.taboption('advanced', form.Value, 'dns_port', _('DNS port'),
			_('Port meow\'s DNS server listens on (dns.listen in the YAML).'));
		o.datatype = 'port';
		o.default = '1053';
		o.depends('dns_hijack', '1');

		o = s.taboption('advanced', form.Flag, 'ipv6', _('Proxy IPv6'),
			_('Also proxy IPv6 TCP. Leave off with fake-ip, which hides IPv6 answers.'));
		o.rmempty = false;
		o.depends('mode', 'redirect');

		o = s.taboption('advanced', form.DynamicList, 'bypass', _('Never proxy these destinations'),
			_('Extra networks (CIDR, e.g. 203.0.113.0/24) that always go direct, on top of private and reserved ranges.'));
		o.datatype = 'cidr';

		return m.render();
	}
});
