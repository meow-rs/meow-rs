'use strict';
'require view';
'require form';
'require dom';
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
			_('Saving updates the local YAML configuration to match these settings. ' +
			  'Save & Apply also restarts the service. Proxies, rules and upstream DNS ' +
			  'remain editable in the Configuration tab.'));

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

		o = s.option(form.DummyValue, '_status', _('Status'));
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

		o = s.option(form.Flag, 'enabled', _('Enable'),
			_('Start the service at boot. Saving & applying restarts the service.'));
		o.rmempty = false;

		o = s.option(form.Value, 'config_file', _('Configuration file'),
			_('Fixed configuration path for the managed service.'));
		o.default = '/etc/meow/config.yaml';
		o.readonly = true;
		o.rmempty = false;

		o = s.option(form.Value, 'work_dir', _('Working directory'),
			_('Directory for GeoIP databases, caches and downloaded rulesets.'));
		o.default = '/etc/meow';
		o.readonly = true;
		o.rmempty = false;

		o = s.option(form.Value, 'panel_port', _('Panel port'),
			_('Port of the REST API / built-in web panel. Saved to external-controller in YAML.'));
		o.datatype = 'port';
		o.default = '9090';
		o.rmempty = false;

		o = s.option(form.Value, 'secret', _('API secret'),
			_('Saved to secret in the YAML configuration, including when cleared. ' +
			  'Clearing it restricts the API and panel to this router; set a secret for LAN access.'));
		o.password = true;

		s = m.section(form.NamedSection, 'tproxy', 'transparent', _('Transparent proxy'),
			_('Proxy traffic that LAN clients route through this device — as the main ' +
			  'router or as a side router (clients use this device as gateway and DNS). ' +
			  'TCP and UDP are handed to the tproxy listener and DNS to meow\'s resolver; ' +
			  'LAN and reserved destinations bypass the proxy. The YAML configuration ' +
			  'is updated automatically with the matching LAN listener and DNS port.'));
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'mode', _('Mode'));
		o.value('tproxy', _('TPROXY (TCP + UDP)'));
		o.value('redirect', _('REDIRECT (TCP only)'));
		o.default = 'tproxy';

		o = s.option(form.ListValue, 'interface', _('LAN interface'),
			_('Clients arriving on this interface are proxied.'));
		uci.sections('network', 'interface', function(sec) {
			if (sec['.name'] !== 'loopback')
				o.value(sec['.name']);
		});
		o.default = 'lan';

		o = s.option(form.Value, 'tproxy_port', _('Tproxy port'),
			_('Port of the LAN listener created in the YAML configuration.'));
		o.datatype = 'port';
		o.default = '7893';

		o = s.option(form.Flag, 'dns_hijack', _('Hijack DNS'),
			_('Redirect all LAN DNS queries (port 53) to meow. Needed for fake-ip mode.'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'dns_port', _('DNS port'),
			_('Saved to dns.listen on 0.0.0.0 when DNS hijacking is enabled.'));
		o.datatype = 'port';
		o.default = '1053';
		o.depends('dns_hijack', '1');

		o = s.option(form.Flag, 'ipv6', _('Proxy IPv6'),
			_('Also redirect IPv6 TCP (REDIRECT mode only). Leave off with fake-ip, which suppresses AAAA answers.'));
		o.rmempty = false;

		o = s.option(form.DynamicList, 'bypass', _('Bypass destinations'),
			_('Extra CIDRs that are never proxied, in addition to private and reserved ranges.'));
		o.datatype = 'cidr';

		return m.render();
	}
});
