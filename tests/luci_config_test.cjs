// Exercise the LuCI view without a router. RPC writes deliberately reject large
// messages, while the multipart endpoint records the exact UTF-8 payload.
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { test } = require('node:test');
const vm = require('node:vm');
const source = readFileSync(require('node:path').join(__dirname,
  '../openwrt/luci-app-meow/htdocs/luci-static/resources/view/meow/config.js'), 'utf8');
const scratchPattern = /^\/tmp\/meow-luci-settings-[0-9a-f]{32}\.yaml$/;
const path = '/etc/meow/config.yaml';

function setup(options = {}) {
  const uploads = [], notifications = [], removed = [], calls = [];
  const content = options.content ?? 'rules:\r\n  - MATCH,🎯Direct';
  const context = vm.createContext({
    Blob, FormData, crypto: require('node:crypto').webcrypto,
    meow: { serviceRunning: async () => !!options.running },
    settings: { prepare: value => {
      if (options.transformError) throw new Error(options.transformError);
      return options.prepare ? options.prepare(value) : value;
    } },
    view: { extend: value => value },
    L: { env: { sessionid: 'test-session', cgi_base: '/cgi-bin' } },
    _: value => value,
    E: (tag, attrs, children) => ({ tag, attrs, children, style: {} }),
    document: { getElementById: () => options.textarea ?? ({ value: content }) },
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
        assert.equal(command, '/usr/libexec/meow-validate');
        assert.match(args[0], /^[0-9a-f]{32}$/);
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
      if (options.onUpload) await options.onUpload(target, payload);
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
  const actions = Array.from(tree.children[3].children).filter(n => n && n.tag === 'button');
  assert.deepEqual(actions.map(b => String(b.children)), ['Revert', 'Validate', 'Save']);
  assert.ok(actions.every(b => b.attrs.type === 'button'));
  await actions[2].attrs.click({});
  const scratch = state.uploads[0].target;
  assert.match(scratch, scratchPattern);
  assert.deepEqual(state.calls, [scratch, 'validate', path]);
  assert.deepEqual(state.uploads.map(u => u.payload), Array(2).fill(state.content.replace(/\r\n/g, '\n')));
  assert.deepEqual(state.removed, [state.uploads[0].target]);
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
    assert.deepEqual(state.removed, [state.uploads[0].target]);
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
    assert.deepEqual(state.removed, [state.uploads[0].target]);
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
  const scratch = state.uploads[0].target;
  assert.match(scratch, scratchPattern);
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
  const scratch = state.uploads[0].target;
  assert.match(scratch, scratchPattern);
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
  const scratch = state.uploads[0].target;
  assert.match(scratch, scratchPattern);
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

test('editor tracks unsaved changes, reverts, and indents with spaces', async () => {
  const textarea = { value: 'a: 1\n', selectionStart: 0, selectionEnd: 0 };
  const state = setup({ textarea, content: 'a: 1\n' });
  state.view.render({ path, content: 'a: 1\n' });
  state.view.updateStatus();
  assert.equal(state.view.dirty, false);
  assert.equal(state.view.revert.disabled, true);
  assert.match(state.view.status.textContent, /Saved/);

  // Tab inserts two spaces at the caret instead of moving focus.
  let prevented = 0;
  textarea.selectionStart = textarea.selectionEnd = 3;
  state.view.handleKey(path, { key: 'Tab', target: textarea, preventDefault: () => prevented++ });
  assert.equal(textarea.value, 'a:   1\n');
  assert.equal(textarea.selectionStart, 5);
  assert.equal(prevented, 1);
  assert.equal(state.view.dirty, true);
  assert.equal(state.view.revert.disabled, false);
  assert.match(state.view.status.textContent, /Unsaved changes/);

  state.view.handleRevert();
  assert.equal(textarea.value, 'a: 1\n');
  assert.equal(state.view.dirty, false);

  // Ctrl/Cmd+S saves; a successful save clears the dirty state.
  textarea.value = 'a: 2\n';
  state.view.updateStatus();
  state.view.handleKey(path, { key: 's', metaKey: true, target: textarea, preventDefault: () => prevented++ });
  await new Promise(r => setImmediate(r));
  for (let i = 0; i < 20 && state.view.dirty; i++) await new Promise(r => setTimeout(r, 5));
  assert.equal(state.uploads.at(-1).payload, 'a: 2\n');
  assert.equal(state.view.dirty, false);
});

// Hold an upload open to exercise keyboard/button races without timing sleeps.
function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}

test('overlapping keyboard saves share one operation and preserve newer edits', { timeout: 2000 }, async () => {
  const entered = deferred(), release = deferred();
  const textarea = { value: 'a: 1\n' };
  const state = setup({ textarea, onUpload: async target => {
    if (target === path) { entered.resolve(); await release.promise; }
  } });
  state.view.render({ path, content: textarea.value });
  const saving = state.view.handleSave(null, path);
  await entered.promise;
  textarea.value = 'a: 2\n';
  state.view.updateStatus();
  const repeated = state.view.handleSave(null, path);
  release.resolve();
  await Promise.all([saving, repeated]);
  assert.equal(state.uploads.filter(u => u.target === path).length, 1);
  assert.equal(textarea.value, 'a: 2\n');
  assert.equal(state.view.saved, 'a: 1\n');
  assert.equal(state.view.dirty, true);
  await state.view.handleSave(null, path);
  assert.equal(state.view.saved, 'a: 2\n');
  assert.equal(state.view.dirty, false);
});

test('concurrent validations use separate scratch files', async () => {
  const state = setup();
  await Promise.all([state.view.validate('a: 1\n'), state.view.validate('a: 2\n')]);
  const targets = state.uploads.map(u => u.target);
  assert.ok(targets.every(t => scratchPattern.test(t)));
  assert.equal(new Set(targets).size, 2);
  assert.deepEqual(state.removed.sort(), targets.sort());
});

test('edits typed during an upload are retained as unsaved', { timeout: 2000 }, async () => {
  const entered = deferred(), release = deferred();
  const textarea = { value: 'a: 1\n' };
  const state = setup({ textarea, onUpload: async target => {
    if (target === path) { entered.resolve(); await release.promise; }
  } });
  state.view.render({ path, content: textarea.value });
  const saving = state.view.handleSave(null, path);
  await entered.promise;
  textarea.value = 'a: 2\n';
  release.resolve();
  await saving;
  assert.equal(textarea.value, 'a: 2\n');
  assert.equal(state.view.saved, 'a: 1\n');
  assert.equal(state.view.dirty, true);
});

test('a failed save releases the guard so the user can retry', async () => {
  const options = { saveError: 'No space left' };
  const state = setup(options);
  await state.view.handleSave(null, path);
  options.saveError = null;
  await state.view.handleSave(null, path);
  assert.equal(state.uploads.filter(u => u.target === path).length, 2);
  assert.match(messages(state), /Configuration saved/);
});
