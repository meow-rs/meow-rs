'use strict';
'require baseclass';
'require rpc';
'require uci';

// Shared helpers for the meow LuCI views. Runtime data comes straight from
// the meow REST API (CORS-enabled), addressed via the UCI `panel_port` and
// `secret` options that the init script passes to meow on the command line.

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

return baseclass.extend({
	apiBase: function() {
		var port = uci.get('meow', 'main', 'panel_port') || '9090';
		return window.location.protocol + '//' + window.location.hostname +
			':' + port;
	},

	secret: function() {
		return uci.get('meow', 'main', 'secret') || '';
	},

	// URL of the built-in web panel; the secret travels in the fragment so it
	// is never sent to the server (the panel stores it in its localStorage).
	panelURL: function() {
		var url = this.apiBase() + '/ui';
		var secret = this.secret();
		return secret ? url + '#token=' + encodeURIComponent(secret) : url;
	},

	api: function(method, path, body) {
		var headers = { 'Content-Type': 'application/json' };
		var secret = this.secret();
		if (secret)
			headers['Authorization'] = 'Bearer ' + secret;

		return fetch(this.apiBase() + path, {
			method: method,
			headers: headers,
			body: body != null ? JSON.stringify(body) : null
		}).then(function(res) {
			if (!res.ok)
				return res.text().then(function(t) {
					throw new Error(t || res.statusText);
				});
			return res.status === 204 ? null : res.json();
		});
	},

	serviceRunning: function() {
		return L.resolveDefault(callServiceList('meow'), {}).then(function(res) {
			try {
				return res['meow']['instances']['meow']['running'] === true;
			} catch (e) {
				return false;
			}
		});
	},

	formatBytes: function(b) {
		return '%1024.2mB'.format(b || 0);
	}
});
