'use strict';
'require view';
'require dom';
'require fs';
'require poll';

// meow runs under procd with stdout/stderr captured into the system log.

function fetchLog() {
	return fs.exec_direct('/sbin/logread', [ '-e', 'meow' ]).then(function(out) {
		var lines = (out || '').replace(/\x1b\[[0-9;]*m/g, '').trim().split('\n');
		return lines.slice(-500).reverse().join('\n') || _('No log entries.');
	}).catch(function(e) {
		return _('Unable to read log: %s').format(e.message);
	});
}

return view.extend({
	load: fetchLog,

	render: function(log) {
		var pre = E('pre', {
			'style': 'white-space: pre-wrap; font-size: 12px; max-height: 75vh; overflow: auto;'
		}, [ log ]);

		poll.add(function() {
			return fetchLog().then(function(text) { dom.content(pre, text); });
		}, 5);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('meow Log')),
			E('div', { 'class': 'cbi-map-descr' }, _('Newest entries first; refreshes every 5 seconds.')),
			E('div', { 'class': 'cbi-section' }, [ pre ])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
