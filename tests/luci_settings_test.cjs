const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');
const resources = join(__dirname, '../openwrt/luci-app-meow/htdocs/luci-static/resources');
function moduleFile(file, globals) {
  return vm.runInNewContext('(function() {\n' + readFileSync(join(resources, file), 'utf8') + '\n})()', {
    _: s => s, baseclass: { extend: x => x }, ...globals
  });
}
const yaml = moduleFile('tools/meow_yaml.js');
const defaults = { panel_port: '9090', secret: '', enabled: '1', mode: 'redirect',
  tproxy_port: '7893', dns_hijack: '1', dns_port: '1053', ipv6: '0' };
const plain = value => JSON.parse(JSON.stringify(value));
const parse = text => plain(yaml.parseDocument(text).toJS());
const transform = moduleFile('tools/meow_settings.js', { yaml }).transform;
const input = `# Private subscription\nallow-lan: true\ndns:\n  enable: true\n  listen: 127.0.0.1:7874\n  nameserver: [https://dns.example/dns-query]\nproxies:\n  - &node {name: 香港, type: ss, server: example.com, port: 443, cipher: aes-128-gcm, password: private}\nrules:\n  - MATCH,香港 # keep rule\n`;

test('imported YAML gets matching gateway, DNS and service settings; unrelated content survives', () => {
  const out = transform(input, defaults);
  const config = parse(out);
  assert.deepEqual(config.proxies, parse(input).proxies);
  assert.deepEqual(config.rules, parse(input).rules);
  assert.match(out, /# Private subscription/);
  assert.match(out, /# keep rule/);
  assert.match(out, /&node/);
  assert.equal(config.dns.listen, '0.0.0.0:1053');
  assert.deepEqual(config.dns.nameserver, ['https://dns.example/dns-query']);
  assert.deepEqual(config.listeners, [{ name: 'tproxy-lan', type: 'tproxy', listen: '0.0.0.0',
    port: 7893, udp: false, firewall: false, 'max-connections': 4096 }]);
  assert.equal(config['routing-mark'], 9527);
  assert.equal(config['external-controller'], '0.0.0.0:9090');
  assert.equal(config.secret, '');
  assert.equal(transform(out, defaults), out);
});

test('port and mode changes update one listener and retain custom listeners', () => {
  const source = input + 'listeners:\n  - {name: custom, type: mixed, listen: 127.0.0.1, port: 8088} # custom comment\n';
  const first = transform(source, defaults);
  const changed = transform(first, { ...defaults, mode: 'tproxy', tproxy_port: '8000', dns_port: '5300', panel_port: '9999', secret: 'new: secret' });
  const config = parse(changed);
  assert.equal(config.listeners.length, 2);
  assert.equal(config.listeners[1].port, 8000);
  assert.equal(config.listeners[1].udp, true);
  assert.equal(config.dns.listen, '0.0.0.0:5300');
  assert.equal(config['external-controller'], '0.0.0.0:9999');
  assert.equal(config.secret, 'new: secret');
  assert.deepEqual(config.listeners[0], parse(source).listeners[0]);
  assert.match(changed, /# custom comment/);
  const disabled = parse(transform(changed, { ...defaults, enabled: '0' }));
  assert.deepEqual(disabled.listeners, [config.listeners[0]]);
});

test('DNS hijack off preserves existing DNS and missing DNS is provisioned only when needed', () => {
  assert.deepEqual(parse(transform(input, { ...defaults, dns_hijack: '0' })).dns, parse(input).dns);
  assert.equal(parse(transform('rules: [MATCH,DIRECT]\n', defaults)).dns.enable, true);
  assert.equal(parse(transform('rules: []\n', { ...defaults, enabled: '0' })).dns, undefined);
});

test('IPv6 redirect uses a dual-stack listener; unsupported IPv6 UDP mode is rejected', () => {
  const config = parse(transform(input, { ...defaults, ipv6: '1' }));
  assert.equal(config.listeners[0].listen, '::');
  assert.equal(config.ipv6, true);
  assert.throws(() => transform(input, { ...defaults, mode: 'tproxy', ipv6: '1' }), /IPv6 capture requires REDIRECT/);
});

test('legacy tproxy shorthand migrates to the externally managed listener', () => {
  assert.equal(parse(transform(input + 'tproxy-port: 7893\n', defaults))['tproxy-port'], undefined);
});

test('aliased DNS is materialized without changing its source', () => {
  const out = parse(transform('defaults: &dns {listen: 127.0.0.1:7874, nameserver: [9.9.9.9]}\ndns: *dns\n', defaults));
  assert.equal(out.defaults.listen, '127.0.0.1:7874');
  assert.equal(out.dns.listen, '0.0.0.0:1053');
  assert.deepEqual(out.dns.nameserver, ['9.9.9.9']);
});

for (const source of ['[broken', 'a: 1\na: 2\n', '[]', 'dns: broken\n', 'listeners: {}\n']) {
  test('rejects malformed config: ' + source, () => assert.throws(() => transform(source, defaults)));
}
for (const overrides of [{ tproxy_port: '0' }, { dns_port: '65536' }, { panel_port: '1;reboot' },
  { dns_port: '7893' }, { panel_port: '7893' }, { mode: 'unknown' }]) {
  test('rejects invalid settings: ' + JSON.stringify(overrides), () => assert.throws(() => transform(input, { ...defaults, ...overrides })));
}

test('custom listener conflicts are rejected instead of silently replacing it', () => {
  assert.throws(() => transform(input + 'listeners: [{name: custom, type: mixed, port: 7893}]\n', defaults), /already used/);
  assert.throws(() => transform(input + 'mixed-port: 7893\n', defaults), /already used/);
});

function setup(options = {}) {
  let live = input, reads = 0;
  const calls = [], removed = [];
  const path = '/etc/meow/selected.yaml';
  const uci = { get: (_, section, key) => {
    if (key === 'config_file') return path;
    if (key === 'work_dir') return '/etc/meow';
    return defaults[key];
  }, sections() {}, load: async () => {} };
  const helper = moduleFile('tools/meow_settings.js', {
    yaml, uci, Blob, FormData, crypto: require('node:crypto').webcrypto,
    L: { env: { sessionid: 'test', cgi_base: '/cgi-bin' } },
    fs: {
      read_direct: async p => {
        assert.equal(p, path);
        if (options.readError) throw new Error('read failed');
        if (++reads === 2 && options.concurrent) live += '# external change\n';
        return live;
      },
      exec: async (cmd, args) => {
        calls.push('validate');
        assert.equal(cmd, '/usr/bin/meow');
        assert.equal(args[1], '/etc/meow');
        assert.match(args[3], /^\/tmp\/meow-luci-settings-[a-f0-9]{32}\.yaml$/);
        return options.invalid ? { code: 1, stdout: 'ERROR invalid candidate' } : { code: 0 };
      },
      remove: async p => removed.push(p)
    },
    request: { post: async (url, data) => {
      assert.equal(url, '/cgi-bin/cgi-upload');
      const p = data.get('filename'), content = await data.get('filedata').text();
      calls.push(p === path ? 'write-live' : 'write-scratch');
      if (options.uploadError) return { ok: true, json: () => ({ failure: true, message: 'upload failed' }) };
      if (p === path) live = content;
      return { ok: true, json: () => ({ size: content.length }) };
    } }
  });
  return { helper, calls, removed, uci, live: () => live };
}

test('validates selected YAML before replacement and can roll back a failed UCI save', async () => {
  const state = setup();
  const rollback = await state.helper.save();
  assert.deepEqual(state.calls, ['write-scratch', 'validate', 'write-live']);
  assert.equal(parse(state.live()).listeners[0].port, 7893);
  await rollback();
  assert.equal(state.live(), input);
  assert.equal(state.removed.length, 1);
});
for (const options of [{ invalid: true }, { concurrent: true }, { readError: true }, { uploadError: true }]) {
  test('failure never replaces YAML: ' + JSON.stringify(options), async () => {
    const state = setup(options);
    await assert.rejects(state.helper.save());
    assert.ok(!state.calls.includes('write-live'));
    assert.equal(state.removed.length, 1);
  });
}

test('Settings map synchronizes after parsing and rolls back when UCI save fails', async () => {
  for (const fail of [false, true]) {
    const state = setup();
    const calls = [];
    function Map() {}
    Map.prototype.section = () => ({ option: () => ({ value() {}, depends() {} }) });
    Map.prototype.render = function() { return this; };
    Map.prototype.save = async function(cb) {
      calls.push('parse');
      await cb();
      calls.push('uci-save');
      if (fail) throw new Error('UCI save failed');
    };
    const view = moduleFile('view/meow/settings.js', {
      view: { extend: x => x }, form: { Map }, uci: state.uci,
      settings: { save: async () => { calls.push('yaml-save'); return state.helper.save(); } }
    });
    const map = view.render();
    if (fail) {
      await assert.rejects(map.save(), /UCI save failed/);
      assert.equal(state.live(), input);
    } else {
      await map.save();
      assert.equal(parse(state.live()).listeners.length, 1);
    }
    assert.deepEqual(calls, ['parse', 'yaml-save', 'uci-save']);
  }
});


test('managed listener keeps custom limits and sniffing options during port changes', () => {
  const source = input + 'listeners:\n  - name: tproxy-lan\n    type: tproxy\n    port: 7893\n    max-connections: 2000 # custom limit\n    tproxy-sni: false\n';
  const result = transform(source, { ...defaults, tproxy_port: '8888' });
  assert.equal(parse(result).listeners[0]['max-connections'], 2000);
  assert.equal(parse(result).listeners[0]['tproxy-sni'], false);
  assert.match(result, /# custom limit/);
});


test('moving DNS listener updates proxy-server resolver self-references', () => {
  const source = 'dns:\n  listen: 127.0.0.1:7874\n  proxy-server-nameserver:\n' +
    '    - udp://127.0.0.1:7874\n    - 127.0.0.1:7874\n    - udp://localhost:7874#DIRECT\n' +
    '    - udp://[::1]:7874\n    - 127.0.0.1:5353\n    - 9.9.9.9\n    - https://dns.example/dns-query\n';
  const result = transform(source, defaults);
  assert.deepEqual(parse(result).dns['proxy-server-nameserver'], [
    'udp://127.0.0.1:1053', '127.0.0.1:1053', 'udp://127.0.0.1:1053#DIRECT',
    'udp://127.0.0.1:1053', '127.0.0.1:5353', '9.9.9.9', 'https://dns.example/dns-query'
  ]);
  const changed = parse(transform(result, { ...defaults, dns_port: '5300' }));
  assert.equal(changed.dns['proxy-server-nameserver'][0], 'udp://127.0.0.1:5300');
  assert.equal(changed.dns['proxy-server-nameserver'][4], '127.0.0.1:5353');
  assert.equal(transform(result, defaults), result);
});

test('DNS self-references remain unchanged when hijacking is disabled', () => {
  const source = 'dns: {listen: "127.0.0.1:7874", proxy-server-nameserver: ["udp://127.0.0.1:7874"]}\n';
  assert.deepEqual(parse(transform(source, { ...defaults, dns_hijack: '0' })).dns, parse(source).dns);
});
