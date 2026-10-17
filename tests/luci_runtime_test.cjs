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

test('timed notifications use the native LuCI API when available', () => {
  const notification = {}, calls = [];
  const ui = {
    addTimeLimitedNotification(...args) {
      assert.equal(this, ui);
      calls.push(args);
      return notification;
    },
    addNotification() { assert.fail('native notifications must not create a fallback banner'); }
  };
  const helper = load('tools/meow.js', {
    baseclass: extend, rpc: { declare: () => () => {} }, ui
  }, { setTimeout: () => assert.fail('the native API owns notification expiry') });
  const content = { tag: 'p' };
  assert.equal(helper.addTimeLimitedNotification('Result', content, 4000, 'info'), notification);
  assert.deepEqual(calls, [['Result', content, 4000, 'info']]);
});

test('timed notifications expire independently with the LuCI 23.05 API', () => {
  const visible = new Set(), notifications = [], timers = [];
  // 23.05: addNotification(title, children, ...classes).
  const ui = { addNotification: (title, children, ...classes) => {
    notifications.push([title, children, ...classes]);
    const classList = new Set(classes);
    const node = { classes: classList, classList: { add: c => classList.add(c) },
      remove: () => visible.delete(node) };
    visible.add(node);
    return node;
  } };
  const helper = load('tools/meow.js', {
    baseclass: extend, rpc: { declare: () => () => {} }, ui
  }, { setTimeout: (callback, timeout) => { timers.push({ callback, timeout }); } });
  const firstContent = { tag: 'p' }, secondContent = { tag: 'pre' };
  const first = helper.addTimeLimitedNotification(null, firstContent, 3000, 'info');
  const second = helper.addTimeLimitedNotification('Result', secondContent, 5000, 'warning');
  assert.deepEqual(notifications, [[null, firstContent, 'info'], ['Result', secondContent, 'warning']]);
  assert.deepEqual([...first.classes], ['info']);
  assert.deepEqual([...second.classes], ['warning']);
  assert.deepEqual(timers.map(t => t.timeout), [3000, 5000]);
  assert.deepEqual([...visible], [first, second]);
  timers[0].callback();
  assert.deepEqual([...visible], [second]);
  timers[1].callback();
  assert.equal(visible.size, 0);
});

test('timed notifications keep their class with the OpenWrt 24.10.0 API', () => {
  // 24.10.0 shipped addNotification(title, children, timeout, ...classes) and
  // no addTimeLimitedNotification(), so the type lands in the timeout slot.
  const calls = [], timers = [];
  const ui = { addNotification: (title, children, timeout, ...classes) => {
    calls.push({ timeout, classes });
    const classList = new Set(classes);
    return { classes: classList, classList: { add: c => classList.add(c) }, remove() {} };
  } };
  const helper = load('tools/meow.js', {
    baseclass: extend, rpc: { declare: () => () => {} }, ui
  }, { setTimeout: (callback, timeout) => { timers.push({ callback, timeout }); } });
  const notification = helper.addTimeLimitedNotification(null, {}, 3000, 'info');
  assert.deepEqual(calls, [{ timeout: 'info', classes: [] }]);
  assert.deepEqual([...notification.classes], ['info']);
  assert.deepEqual(timers.map(t => t.timeout), [3000]);
});

test('manually dismissed timed notifications can expire safely', () => {
  const visible = new Set();
  let expire;
  const helper = load('tools/meow.js', {
    baseclass: extend, rpc: { declare: () => () => {} },
    ui: { addNotification: () => {
      const node = { classList: { add() {} }, remove: () => visible.delete(node) };
      visible.add(node);
      return node;
    } }
  }, { setTimeout: callback => { expire = callback; } });
  const notification = helper.addTimeLimitedNotification(null, {}, 3000, 'info');
  notification.remove();
  assert.equal(visible.size, 0);
  assert.doesNotThrow(() => expire());
  assert.equal(visible.size, 0);
});

for (const action of ['start', 'stop']) {
  test('Overview ' + action + ' reports confirmed success with the LuCI 23.05 API', async () => {
    const notifications = [], timers = [], commands = [];
    const setTimeout = (callback, timeout) => { timers.push({ callback, timeout }); };
    const modules = {
      baseclass: extend, view: extend,
      rpc: { declare: () => async () => ({ meow: { instances: { meow: { running: action !== 'stop' } } } }) },
      fs: { exec: async (...args) => { commands.push(args); return { code: 0 }; } },
      ui: { addNotification: (...args) => {
        notifications.push(args);
        return { classList: { add() {} }, remove() {} };
      } }
    };
    const globals = { setTimeout, L: { resolveDefault: (promise, fallback) => promise.catch(() => fallback) } };
    modules['tools.meow'] = load('tools/meow.js', modules, globals);
    const view = load('view/meow/overview.js', modules, { setTimeout });
    view.nodes = {};
    let refreshed = 0;
    view.refresh = async nodes => { assert.equal(nodes, view.nodes); refreshed++; };
    const operation = view.service(action);
    await Promise.resolve();
    assert.equal(timers[0].timeout, 1500);
    timers[0].callback();
    await operation;
    assert.deepEqual(JSON.parse(JSON.stringify(commands)), [['/etc/init.d/meow', [action]]]);
    assert.deepEqual(notifications.map(n => n[2]), ['info']);
    assert.equal(refreshed, 1);
  });
}

for (const result of [{ code: 1, stderr: 'init failed' }, { code: 0 }]) {
  test('Overview reports a failed start instead of success: ' + JSON.stringify(result), async () => {
    const notifications = [], timers = [];
    const setTimeout = (callback, timeout) => { timers.push({ callback, timeout }); };
    const modules = {
      baseclass: extend, view: extend,
      rpc: { declare: () => async () => ({ meow: { instances: { meow: { running: false } } } }) },
      fs: { exec: async () => result },
      ui: { addNotification: (...args) => {
        notifications.push(args);
        return { classList: { add() {} }, remove() {} };
      } }
    };
    const globals = { setTimeout, L: { resolveDefault: (promise, fallback) => promise.catch(() => fallback) } };
    modules['tools.meow'] = load('tools/meow.js', modules, globals);
    const view = load('view/meow/overview.js', modules, { setTimeout });
    let refreshed = 0;
    view.refresh = async () => { refreshed++; };
    const operation = view.service('start');
    await Promise.resolve();
    if (result.code === 0) timers[0].callback();
    await operation;
    assert.deepEqual(notifications.map(n => n[2]), ['error']);
    assert.equal(refreshed, 1);
  });
}

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
