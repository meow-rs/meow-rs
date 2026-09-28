'use strict';
'require baseclass';
'require fs';
'require request';
'require uci';
'require tools.meow_yaml as yaml';

// This name is also used by the package's default YAML. Other named listeners
// belong to the user; never replace the entire listeners array.
var LISTENER = 'tproxy-lan';

function port(value, label) {
	if (!/^\d+$/.test(String(value)) || Number(value) < 1 || Number(value) > 65535)
		throw new Error(_('Invalid port: ') + label);
	return Number(value);
}

function transform(content, settings) {
	var doc = yaml.parseDocument(content);
	if (doc.errors.length)
		throw new Error(doc.errors[0].message);
	if (!yaml.isMap(doc.contents))
		throw new Error(_('The YAML configuration must be a mapping.'));
	var config = doc.toJS();
	var panelPort = port(settings.panel_port, _('Panel port'));
	var enabled = settings.enabled === '1';
	var ipv6 = settings.ipv6 === '1';
	var udp = settings.mode === 'tproxy';
	if (enabled && settings.mode !== 'redirect' && !udp)
		throw new Error(_('Unknown transparent proxy mode.'));
	if (enabled && ipv6 && udp)
		throw new Error(_('IPv6 capture requires REDIRECT mode; UDP TPROXY supports IPv4 only.'));

	doc.set('external-controller', (settings.secret ? '0.0.0.0:' : '127.0.0.1:') + panelPort);
	doc.set('secret', settings.secret || '');

	var listeners = doc.get('listeners', true), managed;
	if (listeners && !yaml.isSeq(listeners))
		throw new Error(_('listeners must be a YAML sequence.'));
	if (listeners) {
		// Resolve aliases when identifying managed entries, but retain the AST
		// of unrelated entries (including their comments and anchors).
		listeners.items = listeners.items.filter(function(item, i) {
			if (config.listeners[i] && config.listeners[i].name === LISTENER) {
				managed = yaml.isMap(item) ? item : doc.createNode(config.listeners[i]);
				return false;
			}
			return true;
		});
	}
	if (enabled) {
		var proxyPort = port(settings.tproxy_port, _('Tproxy port'));
		var dnsPort = settings.dns_hijack === '1' ? port(settings.dns_port, _('DNS port')) : null;
		if (proxyPort === panelPort || proxyPort === dnsPort || panelPort === dnsPort)
			throw new Error(_('Panel, transparent proxy and DNS ports must be different.'));
		(config.listeners || []).forEach(function(listener) {
			if (listener && listener.name !== LISTENER && Number(listener.port) === proxyPort)
				throw new Error(_('Transparent proxy port is already used by listener: ') + listener.name);
		});
		['port', 'socks-port', 'mixed-port'].forEach(function(key) {
			if (Number(config[key]) === proxyPort)
				throw new Error(_('Transparent proxy port is already used by ') + key);
		});
		if (!listeners) {
			doc.set('listeners', doc.createNode([]));
			listeners = doc.get('listeners', true);
		}
		managed = managed || doc.createNode({ name: LISTENER, 'max-connections': 4096 });
		Object.entries({ type: 'tproxy', listen: ipv6 ? '::' : '0.0.0.0',
			port: proxyPort, udp: udp, firewall: false }).forEach(function(entry) {
			managed.set(entry[0], entry[1]);
		});
		listeners.add(managed);
		// The shorthand installs router-local firewall rules. Replace it with
		// the explicitly externally-managed gateway listener.
		doc.delete('tproxy-port');
		doc.set('routing-mark', 9527);
		if (ipv6)
			doc.set('ipv6', true);
		if (dnsPort !== null) {
			if (config.dns != null && (typeof config.dns !== 'object' || Array.isArray(config.dns)))
				throw new Error(_('dns must be a YAML mapping.'));
			// Materialize an aliased DNS mapping before editing it, avoiding
			// changes to any other consumer of that anchor.
			if (!yaml.isMap(doc.get('dns', true)))
				doc.set('dns', doc.createNode(config.dns || {}));
			// Subscriptions may resolve proxy hostnames through this DNS server.
			// Moving dns.listen must move those self-references too; keeping the
			// old port leaves proxy connections unable to resolve their servers.
			var oldListen = config.dns && config.dns.listen;
			var oldPort = typeof oldListen === 'string' && oldListen.match(/:(\d+)$/);
			var proxyDns = config.dns && config.dns['proxy-server-nameserver'];
			if (oldPort && Array.isArray(proxyDns)) {
				proxyDns.forEach(function(server, i) {
					var local = typeof server === 'string' && server.match(/^(udp:\/\/)?(127\.0\.0\.1|localhost|\[::1\])(?::(\d+))?([#?].*)?$/);
					if (local && Number(local[3] || 53) === Number(oldPort[1]))
						doc.setIn(['dns', 'proxy-server-nameserver', i],
							(local[1] || '') + '127.0.0.1:' + dnsPort + (local[4] || ''));
				});
			}
			doc.setIn(['dns', 'enable'], true);
			doc.setIn(['dns', 'listen'], '0.0.0.0:' + dnsPort);
			if (!config.dns || !config.dns.nameserver || !config.dns.nameserver.length)
				doc.setIn(['dns', 'nameserver'], ['223.5.5.5', '1.1.1.1']);
		}
	}
	return doc.toString({ lineWidth: 0 });
}

function write(path, content) {
	var data = new FormData();
	data.append('sessionid', L.env.sessionid);
	data.append('filename', path);
	data.append('filedata', new Blob([content], { type: 'text/plain' }), 'config.yaml');
	return request.post(L.env.cgi_base + '/cgi-upload', data, { timeout: 0 }).then(function(res) {
		if (!res.ok)
			throw new Error(res.statusText || _('Upload request failed'));
		var reply = res.json();
		if (!reply || reply.failure)
			throw new Error((reply && reply.message) || _('Upload request failed'));
	});
}

function values() {
	function get(section, key, fallback) {
		var value = uci.get('meow', section, key);
		return value == null || value === '' ? fallback : value;
	}
	return {
		panel_port: get('main', 'panel_port', '9090'), secret: get('main', 'secret', ''),
		enabled: get('tproxy', 'enabled', '0'), mode: get('tproxy', 'mode', 'tproxy'),
		tproxy_port: get('tproxy', 'tproxy_port', '7893'),
		dns_hijack: get('tproxy', 'dns_hijack', '1'), dns_port: get('tproxy', 'dns_port', '1053'),
		ipv6: get('tproxy', 'ipv6', '0')
	};
}

return baseclass.extend({
	transform: transform,
	prepare: function(content) { return transform(content, values()); },

	// Called after form.parse(), before UCI is saved/applied. The returned
	// rollback is used if the subsequent UCI save fails.
	save: function() {
		var path = uci.get('meow', 'main', 'config_file') || '/etc/meow/config.yaml';
		if (path !== '/etc/meow/config.yaml' || (uci.get('meow', 'main', 'work_dir') || '/etc/meow') !== '/etc/meow')
			return Promise.reject(new Error(_('LuCI edits require /etc/meow/config.yaml and working directory /etc/meow.')));
		// getRandomValues also works on plain HTTP LuCI pages.
		var token = Array.from(crypto.getRandomValues(new Uint32Array(4)), function(n) {
			return n.toString(16).padStart(8, '0');
		}).join('');
		var scratch = '/tmp/meow-luci-settings-' + token + '.yaml';
		var original, candidate;
		return fs.read_direct(path).then(function(content) {
			original = content;
			candidate = transform(content, values());
			return write(scratch, candidate);
		}).then(function() {
			return fs.exec('/usr/libexec/meow-validate', [token]);
		}).then(function(res) {
			if (res.code !== 0) {
				var output = ((res.stdout || '') + (res.stderr || '')).replace(/\x1b\[[0-9;]*m/g, '');
				var errors = output.split('\n').filter(function(line) { return /ERROR|Error/.test(line); });
				throw new Error(errors.join('\n') || _('Configuration test failed; settings were not saved.'));
			}
			return fs.read_direct(path);
		}).then(function(current) {
			if (current !== original)
				throw new Error(_('Configuration changed during validation. Reload and try again.'));
			return candidate === original ? null : write(path, candidate);
		}).then(function() {
			return function() {
				return fs.read_direct(path).then(function(current) {
					if (current !== candidate)
						throw new Error(_('Cannot restore YAML: configuration was changed by another session.'));
					return write(path, original);
				});
			};
		}).finally(function() {
			return fs.remove(scratch).catch(function() {});
		});
	}
});
