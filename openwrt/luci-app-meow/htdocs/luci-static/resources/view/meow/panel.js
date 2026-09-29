'use strict';
'require view';
'require ui';
'require uci';
'require tools.meow as meow';

// Embeds meow's built-in web panel (served by the meow REST API at /ui)
// instead of reimplementing a dashboard in LuCI. The API secret, if any, is
// handed over in the URL fragment so the panel works without re-entering it.
//
// Without a secret the init script binds the API to 127.0.0.1 only, so the
// browser cannot reach it: explain that and offer to set a password instead
// of embedding a frame that can only fail.

function randomSecret() {
	var bytes = new Uint8Array(32);
	window.crypto.getRandomValues(bytes);
	return Array.prototype.map.call(bytes, function(b) {
		return ('0' + b.toString(16)).slice(-2);
	}).join('');
}

return view.extend({
	load: function() {
		return uci.load('meow');
	},

	// Setting the secret makes meow listen on the LAN (with authentication);
	// applying the UCI change restarts the service through its reload trigger.
	handleEnableLan: function() {
		uci.set('meow', 'main', 'secret', randomSecret());
		return uci.save()
			.then(function() { return uci.apply(); })
			.then(function() { return new Promise(function(r) { setTimeout(r, 3000); }); })
			.then(function() { location.reload(); })
			.catch(function(e) {
				ui.addNotification(null, E('p', _('Failed to set the panel password: %s').format(e.message)), 'error');
			});
	},

	renderLocalOnly: function() {
		return E('div', { 'class': 'alert-message notice' }, [
			E('p', {}, [
				E('strong', {}, _('The panel is only reachable from the router itself.')), ' ',
				_('No panel password (API secret) is set, so meow keeps its web panel off the LAN. ' +
				  'Set a password to open the panel from this browser; LuCI passes it to the panel automatically.')
			]),
			E('p', {}, [
				E('button', {
					'class': 'cbi-button cbi-button-positive',
					'click': ui.createHandlerFn(this, 'handleEnableLan')
				}, _('Generate a password and enable the panel')),
				' ',
				E('a', { 'href': L.url('admin/services/meow/settings') }, _('or choose one in Settings')),
				' ',
				E('small', {}, _('(meow restarts briefly)'))
			])
		]);
	},

	render: function() {
		var url = meow.panelURL();
		var plain = meow.apiBase() + '/ui';
		var body;

		if (!meow.secret())
			body = this.renderLocalOnly();
		else if (window.location.protocol === 'https:')
			body = E('p', {}, _('Open the panel in a new tab. The standalone panel uses HTTP and cannot be embedded in an HTTPS page.'));
		else
			body = E('iframe', {
				'src': url,
				'style': 'width: 100%; min-height: 75vh; border: none;' +
					' border-radius: 3px; background: #0f1923;'
			});

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow Panel')),
			E('div', { 'class': 'cbi-map-descr' }, meow.secret() ? [
				_('Built-in web panel served by the meow REST API. '),
				E('a', { 'href': url, 'target': '_blank', 'rel': 'noopener' },
					_('Open in a new tab')),
				' — ', plain,
				E('br'),
				E('small', {}, _('Blank frame? meow may be stopped (see Overview), or a firewall blocks port %s from your device.')
					.format(uci.get('meow', 'main', 'panel_port') || '9090'))
			] : _('Built-in web panel served by the meow REST API.')),
			body
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
