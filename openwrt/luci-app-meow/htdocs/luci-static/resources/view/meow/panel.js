'use strict';
'require view';
'require uci';
'require tools.meow as meow';

// Embeds meow's built-in web panel (served by the meow REST API at /ui)
// instead of reimplementing a dashboard in LuCI. The API secret, if any, is
// handed over in the URL fragment so the panel works without re-entering it.

return view.extend({
	load: function() {
		return uci.load('meow');
	},

	render: function() {
		var url = meow.panelURL();
		var plain = meow.apiBase() + '/ui';

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow Panel')),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('Built-in web panel served by the meow REST API. '),
				E('a', { 'href': url, 'target': '_blank', 'rel': 'noopener' },
					_('Open in a new tab')),
				' — ', plain
			]),
			window.location.protocol === 'https:'
				? E('p', {}, _('Open the panel in a new tab. The standalone panel uses HTTP and cannot be embedded in an HTTPS page.'))
				: E('iframe', {
				'src': url,
				'style': 'width: 100%; min-height: 75vh; border: none;' +
					' border-radius: 3px; background: #0f1923;'
			})
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
