'use strict';
'require view';
'require fs';
'require request';
'require ui';
'require uci';
'require tools.meow_settings as settings';
'require tools.meow as meow';

// Raw editor for the meow YAML configuration. Edits are validated with
// `meow -t` against a scratch copy before they replace the real file. A running
// service is explicitly restarted after saving. Runtime changes through the
// panel are written back to this file by its "Save Config" button.

var SCRATCH = '/tmp/meow-luci-check.yaml';

// YAML subscriptions can exceed ubus request limits. Use the same authenticated
// multipart upload as LuCI's file picker; cgi-io enforces the file ACLs.
function writeConfig(path, content) {
	var data = new FormData();
	data.append('sessionid', L.env.sessionid);
	data.append('filename', path);
	data.append('filedata', new Blob([ content ], { type: 'text/plain' }), 'config.yaml');

	return request.post(L.env.cgi_base + '/cgi-upload', data, { timeout: 0 }).then(function(res) {
		if (!res.ok)
			throw new Error(res.statusText || _('Upload request failed'));
		var reply = res.json();
		if (!reply || reply.failure)
			throw new Error((reply && reply.message) || _('Upload request failed'));
	});
}

return view.extend({
	load: function() {
		return uci.load('meow').then(function() {
			var path = uci.get('meow', 'main', 'config_file') || '/etc/meow/config.yaml';
			return fs.read_direct(path).then(function(content) {
				return { path: path, content: content };
			});
		});
	},

	validate: function(content) {
		var workDir = uci.get('meow', 'main', 'work_dir') || '/etc/meow';

		return writeConfig(SCRATCH, content).then(function() {
			return fs.exec('/usr/bin/meow', [ '-d', workDir, '-f', SCRATCH, '-t' ]);
		}).then(function(res) {
			if (res.code === 0)
				return null;
			// meow logs to stdout with ANSI colors; keep the error lines.
			var out = ((res.stdout || '') + (res.stderr || ''))
				.replace(/\x1b\[[0-9;]*m/g, '').trim().split('\n');
			var errors = out.filter(function(l) { return /ERROR|Error/.test(l); });
			return (errors.length ? errors : out).join('\n') || _('Configuration test failed');
		}).finally(function() {
			return fs.remove(SCRATCH).catch(function() {});
		});
	},

	handleValidate: function() {
		var content = document.getElementById('meow-yaml').value;
		return Promise.resolve().then(function() {
			content = settings.prepare(content);
			return this.validate(content);
		}.bind(this)).then(function(err) {
			if (err)
				ui.addNotification(_('Invalid configuration'), E('pre', {}, err), 'error');
			else
				ui.addTimeLimitedNotification(null, E('p', _('Configuration test passed')), 3000, 'info');
		}).catch(function(e) {
			ui.addNotification(null, E('p', _('Unable to validate: %s').format(e.message)), 'error');
		});
	},

	handleSave: function(ev, path) {
		var content = document.getElementById('meow-yaml').value.replace(/\r\n/g, '\n');
		if (!/\n$/.test(content))
			content += '\n';

		return Promise.resolve().then(function() {
			content = settings.prepare(content);
			return this.validate(content);
		}.bind(this)).then(function(err) {
			if (err) {
				ui.addNotification(_('Invalid configuration, not saved'), E('pre', {}, err), 'error');
				return;
			}
			return writeConfig(path, content).then(function() {
				document.getElementById('meow-yaml').value = content;
				return meow.serviceRunning().then(function(running) {
					if (!running) return false;
					return fs.exec('/etc/init.d/meow', ['restart']).then(function(res) {
						if (res.code !== 0) throw new Error(res.stderr || _('Service restart failed'));
						return meow.serviceRunning().then(function(active) {
							if (!active) throw new Error(_('Service did not start'));
							return true;
						});
					});
				}).then(function(restarted) {
					ui.addTimeLimitedNotification(null, E('p', restarted
						? _('Configuration saved and service restarted.')
						: _('Configuration saved; service remains stopped.')), 5000, 'info');
				}).catch(function(error) {
					ui.addNotification(null, E('p', _('Configuration saved, but restart failed: %s').format(error.message)), 'error');
				});
			});
		}).catch(function(e) {
			ui.addNotification(null, E('p', _('Unable to save: %s').format(e.message)));
		});
	},

	render: function(data) {
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow Configuration')),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('Raw YAML configuration at %s (mihomo / Clash Meta format). ' +
				  'Settings from the Settings tab are applied and the result is validated before saving.').format(data.path)
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('textarea', {
					'id': 'meow-yaml',
					'class': 'cbi-input-textarea',
					'style': 'width: 100%; min-height: 60vh; font-family: monospace; font-size: 12px;',
					'spellcheck': 'false',
					'wrap': 'off'
				}, [ data.content ])
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', {
					'type': 'button',
					'class': 'cbi-button cbi-button-neutral',
					'click': ui.createHandlerFn(this, 'handleValidate')
				}, _('Validate')),
				' ',
				E('button', {
					'type': 'button',
					'class': 'cbi-button cbi-button-save',
					'click': ui.createHandlerFn(this, 'handleSave', null, data.path)
				}, _('Save'))
			])
		]);
	},

	handleSaveApply: null,
	handleReset: null,
	addFooter: function() { return E('div'); }
});
