// Exercise the LuCI view without a router. RPC writes deliberately reject large
// messages, while the multipart endpoint records the exact UTF-8 payload.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');
const source = readFileSync(require('node:path').join(__dirname,
  '../openwrt/luci-app-meow/htdocs/luci-static/resources/view/meow/config.js'), 'utf8');
const scratch = '/tmp/meow-luci-check.yaml';
const path = '/etc/meow/config.yaml';

function setup(options = {}) {
  const uploads = [], notifications = [], removed = [], calls = [];
  const content = options.content ?? 'rules:\r\n  - MATCH,🎯Direct';
  const context = vm.createContext({
    Blob, FormData,
    meow: { serviceRunning: async () => !!options.running },
    settings: { prepare: value => {
      if (options.transformError) throw new Error(options.transformError);
      return options.prepare ? options.prepare(value) : value;
    } },
    view: { extend: value => value },
    L: { env: { sessionid: 'test-session', cgi_base: '/cgi-bin' } },
    _: value => value,
    E: (tag, attrs, children) => ({ tag, attrs, children }),
    document: { getElementById: () => ({ value: content }) },
    uci: { load: async () => {}, get: () => undefined },
    ui: {
      addNotification: (...args) => notifications.push(args),
      addTimeLimitedNotification: (...args) => notifications.push(args),
      createHandlerFn: (ctx, fn, ...args) => (...rest) => ctx[fn](...args, ...rest)
    },
    fs: {
      read: async () => { throw new Error('RPC read must not be used'); },
      read_direct: async p => {
        assert.equal(p, path);
        if (options.readError) throw new Error(options.readError);
        return content;
      },
      write: async () => { throw new Error('XHR request aborted by browser'); },
      exec: async (command, args) => {
        if (command === '/etc/init.d/meow') {
          assert.deepEqual(Array.from(args), ['restart']);
          calls.push('restart');
          return options.restartResult ?? { code: 0 };
        }
        assert.equal(command, '/usr/bin/meow');
        assert.deepEqual(Array.from(args), ['-d', '/etc/meow', '-f', scratch, '-t']);
        calls.push('validate');
        if (options.execError) throw new Error(options.execError);
        return options.result ?? { code: 0 };
      },
      remove: async p => { removed.push(p); }
    },
    request: { post: async (url, data, opts) => {
      assert.equal(url, '/cgi-bin/cgi-upload');
      assert.equal(opts.timeout, 0);
      assert.equal(data.get('sessionid'), 'test-session');
      const target = data.get('filename');
      const payload = await data.get('filedata').text();
      uploads.push({ target, payload });
      calls.push(target);
      if (target === path && options.saveError) throw new Error(options.saveError);
      if (options.networkError) throw new Error(options.networkError);
      return {
        ok: !options.httpError,
        statusText: options.httpError,
        json: () => options.reply ?? { size: Buffer.byteLength(payload) }
      };
    } }
  });
  vm.runInContext("String.prototype.format = function(value) { return this.replace('%s', value); };", context);
  const view = vm.runInContext('(function() {\n' + source + '\n})()', context);
  return { view, content, uploads, notifications, removed, calls };
}

function messages(state) { return JSON.stringify(state.notifications); }

test('large Unicode YAML loads and saves without RPC file transfers', async () => {
  const state = setup({ content: 'rules:\r\n' + '  - DOMAIN,例子.test,🎯Direct\r\n'.repeat(50000) });
  assert.ok(Buffer.byteLength(state.content) > 1024 * 1024);
  assert.equal((await state.view.load()).content, state.content);
  // Invoke the actual rendered Save handler, including its bound path.
  const tree = state.view.render({ path, content: state.content });
  const actions = tree.children[3].children;
  assert.equal(actions[0].attrs.type, 'button');
  assert.equal(actions[2].attrs.type, 'button');
  await actions[2].attrs.click({});
  assert.deepEqual(state.calls, [scratch, 'validate', path]);
  assert.deepEqual(state.uploads.map(u => u.payload), Array(2).fill(state.content.replace(/\r\n/g, '\n')));
  assert.deepEqual(state.removed, [scratch]);
  assert.match(messages(state), /Configuration saved/);
  assert.doesNotMatch(JSON.stringify(tree), /<code>/);
});

test('saving appends a trailing newline', async () => {
  const state = setup();
  await state.view.handleSave(null, path);
  assert.equal(state.uploads[1].payload, 'rules:\n  - MATCH,🎯Direct\n');
});

for (const result of [{ code: 1, stderr: '\x1b[31mERROR bad YAML\x1b[0m' }, { code: 1 }]) {
  test('invalid configuration never replaces the live file: ' + JSON.stringify(result), async () => {
    const state = setup({ result });
    await state.view.handleSave(null, path);
    assert.equal(state.uploads.length, 1);
    assert.match(messages(state), /Invalid configuration, not saved/);
    assert.deepEqual(state.removed, [scratch]);
  });
}

for (const options of [
  { reply: { failure: [6, 'Permission denied'], message: 'Permission denied' } },
  { httpError: 'Forbidden' },
  { networkError: 'Disconnected' },
  { execError: 'Command timed out' }
]) {
  test('failed transfer/validation is reported and never saves: ' + JSON.stringify(options), async () => {
    const state = setup(options);
    await state.view.handleSave(null, path);
    assert.equal(state.uploads.length, 1);
    assert.deepEqual(state.removed, [scratch]);
    assert.match(messages(state), /Unable to save/);
    assert.doesNotMatch(messages(state), /Configuration saved/);
  });
}

test('Validate reports transport errors', async () => {
  const state = setup({ execError: 'Command timed out' });
  await state.view.handleValidate();
  assert.match(messages(state), /Unable to validate.*Command timed out/);
});

test('a failed final upload does not claim the configuration was saved', async () => {
  const state = setup({ saveError: 'No space left on device' });
  await state.view.handleSave(null, path);
  assert.deepEqual(state.calls, [scratch, 'validate', path]);
  assert.match(messages(state), /Unable to save.*No space left on device/);
  assert.doesNotMatch(messages(state), /Configuration saved/);
});

test('read failures cannot silently turn an existing configuration into an empty editor', async () => {
  const state = setup({ readError: 'Permission denied' });
  await assert.rejects(state.view.load(), /Permission denied/);
});

// Imported subscriptions must not remove the gateway configuration selected
// in Settings. Use the shipped parser/transformer, not an emulated YAML edit.
test('Configuration Save reapplies LuCI settings before validation and live upload', async () => {
  const resources = require('node:path').join(__dirname, '../openwrt/luci-app-meow/htdocs/luci-static/resources');
  const load = (name, globals = {}) => vm.runInNewContext('(function() {' +
    readFileSync(require('node:path').join(resources, name), 'utf8') + '\n})()',
    { _: s => s, baseclass: { extend: x => x }, ...globals });
  const yaml = load('tools/meow_yaml.js');
  const helper = load('tools/meow_settings.js', { yaml, uci: { get: (_, section, key) => ({
    enabled: '1', mode: 'redirect', dns_hijack: '1', tproxy_port: '7893', dns_port: '1053', panel_port: '9090'
  })[key] } });
  const state = setup({ content: 'rules: []\ndns: {enable: true, listen: 127.0.0.1:7874}\n', prepare: helper.prepare });
  await state.view.handleSave(null, path);
  assert.deepEqual(state.calls, [scratch, 'validate', path]);
  const saved = yaml.parseDocument(state.uploads[1].payload).toJS();
  assert.equal(saved.listeners[0].port, 7893);
  assert.equal(saved.dns.listen, '0.0.0.0:1053');
});

test('YAML synchronization errors prevent uploads and are reported', async () => {
  const state = setup({ transformError: 'Conflicting listener' });
  await state.view.handleSave(null, path);
  assert.equal(state.uploads.length, 0);
  assert.match(messages(state), /Conflicting listener/);
});

test('saving reloads a running service after writing the validated YAML', async () => {
  const state = setup({ running: true });
  await state.view.handleSave(null, path);
  assert.deepEqual(state.calls, [scratch, 'validate', path, 'restart']);
  assert.match(messages(state), /service restarted/);
});

test('saving does not start a stopped service', async () => {
  const state = setup();
  await state.view.handleSave(null, path);
  assert.ok(!state.calls.includes('restart'));
  assert.match(messages(state), /remains stopped/);
});

test('restart failure is distinguished from a successful disk save', async () => {
  const state = setup({ running: true, restartResult: { code: 1, stderr: 'invalid config' } });
  await state.view.handleSave(null, path);
  assert.match(messages(state), /saved, but restart failed/);
  assert.doesNotMatch(messages(state), /service restarted/);
});
