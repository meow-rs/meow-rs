const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const root = join(__dirname, '../openwrt/luci-app-meow/htdocs/luci-static/resources');
function load(file, modules, globals = {}) {
  const source = readFileSync(join(root, file), 'utf8');
  const scope = { _: x => x, E: (tag, attrs, children) => ({ tag, attrs, children }), ...globals };
  // Match LuCI's explicit dependency injection; undeclared modules are absent.
  for (const [, path, alias] of source.matchAll(/'require ([\w.]+)(?: as (\w+))?';/g)) {
    scope[alias || path] = modules[path];
  }
  // LuCI's String.prototype.format, reduced to %s/%d substitution.
  const format = 'String.prototype.format = function() { var a = arguments, i = 0; ' +
    'return this.replace(/%[sd]/g, function() { return a[i++]; }); };';
  return vm.runInNewContext(format + '(function() {' + source + '\n})()', scope);
}
const extend = { extend: x => x };

test('Overview refresh populates status with only declared dependencies', async () => {
  const el = () => ({ style: {}, value: undefined });
  const nodes = { banner: {}, service: {}, gateway: {}, modeHelp: {}, rate: {}, totals: {}, conns: {},
    modeButtons: [], actions: { start: el(), stop: el(), restart: el() } };
  const view = load('view/meow/overview.js', {
    view: extend, dom: { content: (node, value) => { node.value = value; } },
    fs: { exec: async () => ({ code: 0 }) }, uci: { get: () => '0' },
    ui: { createHandlerFn: () => () => {} },
    'tools.meow': { serviceRunning: async () => true, api: async () => null }
  }, { L: { resolveDefault: p => p, url: (...p) => p.join('/') } });
  await view.refresh(nodes);
  assert.equal(nodes.service.value[0].children, 'Running');
  assert.equal(nodes.banner.value, '');
  assert.equal(nodes.conns.value, '-');
  assert.equal(nodes.actions.start.style.display, 'none');
  assert.equal(nodes.actions.stop.style.display, '');
});

test('Overview explains a disabled service and offers to enable it', async () => {
  const el = () => ({ style: {} });
  const nodes = { banner: {}, service: {}, gateway: {}, modeHelp: {}, rate: {}, totals: {}, conns: {},
    modeButtons: [], actions: { start: el(), stop: el(), restart: el() } };
  const view = load('view/meow/overview.js', {
    view: extend, dom: { content: (node, value) => { node.value = value; } },
    fs: { exec: async () => ({ code: 1 }) }, uci: { get: () => '0' },
    ui: { createHandlerFn: (ctx, name) => name },
    'tools.meow': { serviceRunning: async () => false, api: async () => { throw new Error('down'); } }
  }, { L: { resolveDefault: p => p.catch(() => null), url: (...p) => p.join('/') } });
  await view.refresh(nodes);
  assert.equal(nodes.service.value.children, 'Disabled');
  assert.match(JSON.stringify(nodes.banner.value), /not enabled.*handleEnable/);
  assert.equal(nodes.actions.start.style.display, '');
  assert.equal(nodes.actions.restart.style.display, 'none');
});

test('Log polling has an explicitly imported DOM dependency; filters and highlights', async () => {
  let refresh;
  let log = 'a INFO started\nb WARN slow\nc ERROR boom';
  const el = (tag, attrs, children) => ({ tag, attrs: attrs || {}, children, style: {}, value: '',
    classList: { toggle() {} }, scrollHeight: 0, scrollTop: 0, clientHeight: 0 });
  const view = load('view/meow/log.js', {
    view: extend, dom: { content: (node, value) => { node.children = value; } },
    poll: { add: fn => { refresh = fn; } }, fs: { exec_direct: async () => log },
    ui: { createHandlerFn: () => () => {} }
  }, { E: el, L: { bind: (fn, ctx) => fn.bind(ctx) } });
  view.render(['old log']);
  view.levelSel.value = 'all';
  await refresh();
  const text = () => [].concat(view.pre.children).map(n => n.children);
  assert.deepEqual(text(), ['a INFO started', 'b WARN slow', 'c ERROR boom']);
  assert.equal(view.pre.children[2].attrs.style, 'color: #c62828;');
  assert.equal(view.pre.children[1].attrs.style, 'color: #ef6c00;');
  view.levelSel.value = 'warn';
  view.show();
  assert.deepEqual(text(), ['b WARN slow', 'c ERROR boom']);
  view.levelSel.value = 'all';
  view.filter.value = 'boom';
  view.show();
  assert.deepEqual(text(), ['c ERROR boom']);
  // Paused: polling keeps the current view.
  view.filter.value = '';
  view.show();
  view.pauseBtn.textContent = '';
  view.handlePause();
  log = 'd INFO new';
  await refresh();
  assert.equal(text().length, 3);
});

for (const protocol of ['http:', 'https:']) {
  test(protocol + ' Overview API uses authenticated RPC; panel uses HTTP', async () => {
    const calls = [];
    const uci = { get: (c, s, o) => (o === 'secret' ? 'abc' : null) };
    const api = load('tools/meow.js', {
      baseclass: extend, rpc: { declare: () => async () => ({}) }, uci,
      fs: { exec: async (...args) => { calls.push(args); return { code: 0, stdout: '{"version":"test"}' }; } }
    }, { window: { location: { protocol, hostname: 'router.test' } } });
    assert.equal((await api.api('GET', '/version')).version, 'test');
    assert.deepEqual(JSON.parse(JSON.stringify(calls)), [['/usr/libexec/meow-api', ['GET', '/version']]]);
    assert.equal(api.panelURL(), 'http://router.test:9090/ui#token=abc');
    const panel = load('view/meow/panel.js', { view: extend, 'tools.meow': api, uci, ui: {} },
      { window: { location: { protocol } } });
    const tree = panel.render();
    assert.equal(tree.children.some(n => n.tag === 'iframe'), protocol === 'http:');
    assert.match(JSON.stringify(tree), /http:\/\/router.test:9090\/ui/);
  });
}

test('Panel without an API secret explains loopback-only access instead of a blank frame', async () => {
  const writes = [];
  const uci = {
    get: () => null, set: (...a) => writes.push(a), save: async () => {}, apply: async () => {}
  };
  const api = load('tools/meow.js', { baseclass: extend, rpc: { declare: () => () => {} }, uci },
    { window: { location: { protocol: 'http:', hostname: 'router.test' } } });
  const panel = load('view/meow/panel.js', {
    view: extend, 'tools.meow': api, uci, ui: { createHandlerFn: (ctx, name) => name }
  }, { window: { location: { protocol: 'http:' } }, L: { url: p => p } });
  const tree = panel.render();
  assert.ok(!tree.children.some(n => n && n.tag === 'iframe'));
  assert.match(JSON.stringify(tree), /only reachable from the router.*handleEnableLan/);
});

test('API bridge errors propagate instead of rendering success', async () => {
  const api = load('tools/meow.js', {
    baseclass: extend, rpc: { declare: () => () => {} },
    fs: { exec: async () => ({ code: 22, stderr: 'API unauthorized' }) }
  });
  await assert.rejects(api.api('GET', '/configs'), /API unauthorized/);
});

test('mode changes accept an empty successful API response', async () => {
  const api = load('tools/meow.js', {
    baseclass: extend, rpc: { declare: () => () => {} },
    fs: { exec: async () => ({ code: 0 }) }
  });
  assert.equal(await api.api('PATCH', '/configs', { mode: 'direct' }), null);
});
