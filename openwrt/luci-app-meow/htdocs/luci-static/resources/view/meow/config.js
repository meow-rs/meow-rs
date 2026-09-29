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
		// Isolate simultaneous saves/validations, including other browser tabs.
		// Reuse the token path supported by the validator and upload ACL.
		var token = Array.from(crypto.getRandomValues(new Uint32Array(4)), function(n) {
			return n.toString(16).padStart(8, '0');
		}).join('');
		var scratch = '/tmp/meow-luci-settings-' + token + '.yaml';

		return writeConfig(scratch, content).then(function() {
			return fs.exec('/usr/libexec/meow-validate', [token]);
		}).then(function(res) {
			if (res.code === 0)
				return null;
			// meow logs to stdout with ANSI colors; keep the error lines.
			var out = ((res.stdout || '') + (res.stderr || ''))
				.replace(/\x1b\[[0-9;]*m/g, '').trim().split('\n');
			var errors = out.filter(function(l) { return /ERROR|Error/.test(l); });
			return (errors.length ? errors : out).join('\n') || _('Configuration test failed');
		}).finally(function() {
			return fs.remove(scratch).catch(function() {});
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
		if (this.saving) return this.saving;
		var self = this;
		var textarea = document.getElementById('meow-yaml');
		var original = textarea.value;
		var content = original.replace(/\r\n/g, '\n');
		if (!/\n$/.test(content))
			content += '\n';

		return this.saving = Promise.resolve().then(function() {
			content = settings.prepare(content);
			return this.validate(content);
		}.bind(this)).then(function(err) {
			if (err) {
				ui.addNotification(_('Invalid configuration, not saved'), E('pre', {}, err), 'error');
				return;
			}
			return writeConfig(path, content).then(function() {
				// Keep edits entered while validation/upload was in progress.
				if (textarea.value === original) textarea.value = content;
				self.saved = content;
				self.updateStatus();
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
		}).finally(function() {
			self.saving = null;
		});
	},

	// Editor status line: size, line count and whether the text differs from
	// the file on disk. `saved` tracks the last content written or loaded.
	updateStatus: function(text) {
		if (text == null) {
			var ta = document.getElementById('meow-yaml');
			if (!ta) return;
			text = ta.value;
		}
		if (!this.status) return;
		this.dirty = text !== this.saved;
		var lines = text ? text.split('\n').length : 0;
		this.status.textContent = _('%d lines · %s').format(lines, '%1024.1mB'.format(text.length)) +
			' · ' + (this.dirty ? _('Unsaved changes') : _('Saved'));
		this.status.style.color = this.dirty ? '#ef6c00' : '#888';
		if (this.revert) this.revert.disabled = !this.dirty;
	},

	handleRevert: function() {
		var ta = document.getElementById('meow-yaml');
		ta.value = this.saved;
		this.updateStatus();
	},

	// Tab indents with two spaces (YAML forbids tabs); Ctrl/Cmd+S saves.
	handleKey: function(path, ev) {
		var ta = ev.target;
		if (ev.key === 'Tab' && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
			ev.preventDefault();
			var start = ta.selectionStart, end = ta.selectionEnd;
			ta.value = ta.value.slice(0, start) + '  ' + ta.value.slice(end);
			ta.selectionStart = ta.selectionEnd = start + 2;
			this.updateStatus();
		} else if (ev.key === 's' && (ev.ctrlKey || ev.metaKey)) {
			ev.preventDefault();
			this.handleSave(ev, path);
		}
	},

	render: function(data) {
		var self = this;
		this.saved = data.content;
		this.status = E('span', { 'style': 'color: #888;' });

		// Leaving with unsaved edits asks first.
		if (typeof window !== 'undefined' && window.addEventListener)
			window.addEventListener('beforeunload', function(ev) {
				if (self.dirty) { ev.preventDefault(); ev.returnValue = ''; }
			});

		this.revert = E('button', {
			'type': 'button',
			'class': 'cbi-button cbi-button-reset',
			'disabled': true,
			// Plain handler: createHandlerFn would re-enable the button afterwards.
			'click': function() { self.handleRevert(); }
		}, _('Revert'));

		var node = E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow Configuration')),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('Raw YAML configuration at %s (mihomo / Clash Meta format). ' +
				  'Settings from the Settings tab are applied and the result is validated before saving; ' +
				  'an invalid configuration is never written. Tab indents, Ctrl/Cmd+S saves.').format(data.path)
			]),
			E('div', { 'class': 'cbi-section' }, [
				E('textarea', {
					'id': 'meow-yaml',
					'class': 'cbi-input-textarea',
					'style': 'width: 100%; min-height: 60vh; font-family: monospace; font-size: 12px; tab-size: 2;',
					'spellcheck': 'false',
					'wrap': 'off',
					'input': function() { self.updateStatus(); },
					'keydown': function(ev) { self.handleKey(data.path, ev); }
				}, [ data.content ]),
				E('div', { 'style': 'margin-top: .3em; font-size: 12px;' }, [ this.status ])
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				this.revert,
				' ',
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
		this.updateStatus(data.content);
		return node;
	},

	handleSaveApply: null,
	handleReset: null,
	addFooter: function() { return E('div'); }
});
