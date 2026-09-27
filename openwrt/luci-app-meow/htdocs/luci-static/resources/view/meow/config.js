'use strict';
'require view';
'require fs';
'require ui';
'require uci';

// Raw editor for the meow YAML configuration. Edits are validated with
// `meow -t` against a scratch copy before they replace the real file; procd
// restarts meow when the file changes. Changes made at runtime through the
// panel are written back to this file by its "Save Config" button.

var SCRATCH = '/tmp/meow-luci-check.yaml';

return view.extend({
	load: function() {
		return uci.load('meow').then(function() {
			var path = uci.get('meow', 'main', 'config_file') || '/etc/meow/config.yaml';
			return L.resolveDefault(fs.read(path), '').then(function(content) {
				return { path: path, content: content };
			});
		});
	},

	validate: function(content) {
		var workDir = uci.get('meow', 'main', 'work_dir') || '/etc/meow';

		return fs.write(SCRATCH, content).then(function() {
			return fs.exec('/usr/bin/meow', [ '-d', workDir, '-f', SCRATCH, '-t' ]);
		}).then(function(res) {
			fs.remove(SCRATCH).catch(function() {});
			if (res.code === 0)
				return null;
			// meow logs to stdout with ANSI colors; keep the error lines.
			var out = ((res.stdout || '') + (res.stderr || ''))
				.replace(/\x1b\[[0-9;]*m/g, '').trim().split('\n');
			var errors = out.filter(function(l) { return /ERROR|Error/.test(l); });
			return (errors.length ? errors : out).join('\n');
		});
	},

	handleValidate: function() {
		var content = document.getElementById('meow-yaml').value;
		return this.validate(content).then(function(err) {
			if (err)
				ui.addNotification(_('Invalid configuration'), E('pre', {}, err), 'error');
			else
				ui.addTimeLimitedNotification(null, E('p', _('Configuration test passed')), 3000, 'info');
		});
	},

	handleSave: function(ev, path) {
		var content = document.getElementById('meow-yaml').value.replace(/\r\n/g, '\n');
		if (!/\n$/.test(content))
			content += '\n';

		return this.validate(content).then(function(err) {
			if (err) {
				ui.addNotification(_('Invalid configuration, not saved'), E('pre', {}, err), 'error');
				return;
			}
			return fs.write(path, content).then(function() {
				ui.addTimeLimitedNotification(null,
					E('p', _('Configuration saved; meow restarts if it is running.')), 5000, 'info');
			});
		}).catch(function(e) {
			ui.addNotification(null, E('p', _('Unable to save: %s').format(e.message)));
		});
	},

	render: function(data) {
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow Configuration')),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('Raw YAML configuration at <code>%s</code> (mihomo / Clash Meta format). ' +
				  'It is validated with <code>meow -t</code> before saving.').format(data.path)
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
					'class': 'cbi-button cbi-button-neutral',
					'click': ui.createHandlerFn(this, 'handleValidate')
				}, _('Validate')),
				' ',
				E('button', {
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
