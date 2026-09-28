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
  return vm.runInNewContext('(function() {' + source + '\n})()', scope);
}
const extend = { extend: x => x };

test('Overview refresh populates status with only declared dependencies', async () => {
  const nodes = { service: {}, api: {}, gateway: {}, traffic: {}, conns: {}, modeButtons: [] };
  const view = load('view/meow/overview.js', {
    view: extend, dom: { content: (node, value) => { node.value = value; } },
    fs: { exec: async () => ({ code: 0 }) }, uci: { get: () => '0' },
    'tools.meow': { serviceRunning: async () => true, api: async () => null }
  }, { L: { resolveDefault: p => p } });
  await view.refresh(nodes);
  assert.equal(nodes.service.value.children, 'RUNNING');
  assert.equal(nodes.conns.value, '-');
});

test('Log polling has an explicitly imported DOM dependency', async () => {
  let refresh;
  const view = load('view/meow/log.js', {
    view: extend, dom: { content: (node, value) => { node.children = value; } },
    poll: { add: fn => { refresh = fn; } }, fs: { exec_direct: async () => 'new log' }
  });
  const tree = view.render('old log');
  await refresh();
  assert.equal(tree.children[2].children[0].children, 'new log');
});

for (const protocol of ['http:', 'https:']) {
  test(protocol + ' Overview API uses authenticated RPC; panel uses HTTP', async () => {
    const calls = [];
    const api = load('tools/meow.js', {
      baseclass: extend, rpc: { declare: () => async () => ({}) }, uci: { get: () => null },
      fs: { exec: async (...args) => { calls.push(args); return { code: 0, stdout: '{"version":"test"}' }; } }
    }, { window: { location: { protocol, hostname: 'router.test' } } });
    assert.equal((await api.api('GET', '/version')).version, 'test');
    assert.deepEqual(JSON.parse(JSON.stringify(calls)), [['/usr/libexec/meow-api', ['GET', '/version']]]);
    assert.equal(api.panelURL(), 'http://router.test:9090/ui');
    const panel = load('view/meow/panel.js', { view: extend, 'tools.meow': api },
      { window: { location: { protocol } } });
    const tree = panel.render();
    assert.equal(tree.children.some(n => n.tag === 'iframe'), protocol === 'http:');
    assert.match(JSON.stringify(tree), /http:\/\/router.test:9090\/ui/);
  });
}

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
