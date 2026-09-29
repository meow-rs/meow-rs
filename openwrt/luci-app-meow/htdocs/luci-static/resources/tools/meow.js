'use strict';
'require baseclass';
'require rpc';
'require fs';
'require uci';

// Shared helpers for the meow LuCI views. Runtime data comes straight from
// the meow REST API through authenticated LuCI RPC. The standalone panel
// uses the HTTP endpoint configured by the UCI panel_port and secret options.

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

return baseclass.extend({
	apiBase: function() {
		var port = uci.get('meow', 'main', 'panel_port') || '9090';
		return 'http://' + window.location.hostname +
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
		// LuCI RPC stays on the page's authenticated origin, including HTTPS.
		// The helper connects to loopback and reads the API secret from UCI.
		var args = [method, path];
		if (body != null) args.push(JSON.stringify(body));
		return fs.exec('/usr/libexec/meow-api', args).then(function(res) {
			if (res.code !== 0)
				throw new Error(res.stderr || _('Unable to reach meow API'));
			return (res.stdout || '').trim() ? JSON.parse(res.stdout) : null;
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
