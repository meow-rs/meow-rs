const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const root = join(__dirname, '../openwrt/luci-app-meow/htdocs/luci-static/resources');

// Minimal LuCI shims: E() builds plain nodes, `checked: ''` maps to a live
// `.checked` property like the real DOM, and uci is an in-memory store.
function load(config, dhcpHosts = []) {
  const store = JSON.parse(JSON.stringify(config));
  const writes = [];
  const execs = [];
  const E = (tag, attrs, children) => {
    const node = { tag, attrs: attrs || {}, children, style: {} };
    if (tag === 'input') node.checked = node.attrs.checked === '';
    return node;
  };
  const uci = {
    load: async () => {},
    get: (c, s, o) => (store[s] || {})[o],
    set: (c, s, o, v) => { writes.push(['set', s, o, v]); (store[s] = store[s] || {})[o] = v; },
    unset: (c, s, o) => { writes.push(['unset', s, o]); if (store[s]) delete store[s][o]; },
    sections: (c, type, cb) => { if (c === 'dhcp') dhcpHosts.forEach(cb); },
    save: async () => {},
    apply: async () => {}
  };
  const modules = {
    view: { extend: x => x },
    fs: { exec: async (...args) => { execs.push(args); return { code: 0 }; } },
    rpc: { declare: () => async () => ({}) },
    uci,
    ui: { createHandlerFn: () => () => {}, addTimeLimitedNotification: () => {}, addNotification: () => {} }
  };
  const source = readFileSync(join(root, 'view/meow/clients.js'), 'utf8');
  const scope = { _: x => x, E, L: { resolveDefault: p => p } };
  for (const [, path] of source.matchAll(/'require ([\w.]+)';/g)) scope[path] = modules[path];
  // LuCI adds String.prototype.format; emulate %d/%s substitution.
  const view = vm.runInNewContext(
    'String.prototype.format = function() { var a = arguments, i = 0; ' +
    'return this.replace(/%[ds]/g, function() { return a[i++]; }); };' +
    '(function() {' + source + '\n})()', scope);
  return { view, store, writes, execs };
}

const hints = {
  'AA:BB:CC:00:00:01': { name: 'laptop', ipaddrs: ['192.168.1.20'], ip6addrs: ['fd00::20'] },
  'AA:BB:CC:00:00:02': { ipaddrs: ['192.168.1.3'] },
  'AA:BB:CC:00:00:03': { name: 'nas', ipaddrs: ['192.168.1.9'] }
};
const leases = { dhcp_leases: [{ macaddr: 'AA:BB:CC:00:00:04', hostname: 'phone', ipaddr: '192.168.1.50' }] };
const base = { tproxy: { enabled: '1' }, arp: { enabled: '0' } };

const plain = v => JSON.parse(JSON.stringify(v));
function text(node) {
  return JSON.stringify(node, (k, v) => (k === 'style' ? undefined : v));
}
function tableRows(tree) {
  return tree.children[2].children[0].children;
}

test('rows show hostname, IP, MAC and source; unnamed clients fall back to -', () => {
  const { view } = load(base, [{ mac: 'aa:bb:cc:00:00:03' }]);
  const rows = view.buildClients(hints, leases, { 'aa:bb:cc:00:00:03': true }, [], []);
  assert.deepEqual(plain(rows).map(r => [r.name, r.ip4[0], r.mac, r.source]), [
    ['laptop', '192.168.1.20', 'aa:bb:cc:00:00:01', 'neighbour'],
    ['nas', '192.168.1.9', 'aa:bb:cc:00:00:03', 'static'],
    ['phone', '192.168.1.50', 'aa:bb:cc:00:00:04', 'dhcp'],
    ['', '192.168.1.3', 'aa:bb:cc:00:00:02', 'neighbour']
  ]);
  const tree = view.render([null, null, hints, leases]);
  const body = text(tableRows(tree));
  assert.match(body, /"laptop"/);
  assert.match(body, /192\.168\.1\.20/);
  assert.match(body, /fd00::20/);
  assert.match(body, /"Static"/);
  assert.match(text(tableRows(tree)[4]), /"-"/);
});

test('selected MACs that are not currently seen render as offline', () => {
  const { view } = load({ ...base, tproxy: { enabled: '1', bypass_mac: ['AA:BB:CC:99:99:99'] } });
  const tree = view.render([null, null, {}, {}]);
  assert.match(text(tableRows(tree)[1]), /aa:bb:cc:99:99:99.*"Offline"/);
  assert.equal(view.bypassChecks['aa:bb:cc:99:99:99'].checked, true);
});

test('Steer column is hidden unless ARP steering is enabled', () => {
  for (const enabled of ['0', '1']) {
    const { view } = load({ ...base, arp: { enabled } });
    const tree = view.render([null, null, hints, leases]);
    const header = tableRows(tree)[0].children[1];
    assert.equal(header.children, 'Steer');
    assert.equal(header.attrs.style, enabled === '1' ? '' : 'display: none;');
    view.showSteer(true);
    assert.ok(view.arpOnly.every(c => c.style.display === ''));
  }
});

test('Save writes lowercase bypass MACs and keeps hidden steer selections', async () => {
  const cfg = { ...base, arp: { enabled: '1', client: ['aa:bb:cc:00:00:02'] } };
  const { view, store, execs } = load(cfg);
  view.render([null, null, hints, leases]);
  view.bypassChecks['aa:bb:cc:00:00:01'].checked = true;
  view.arpToggle.checked = false;
  await view.handleSaveApply();
  assert.deepEqual(plain(store.tproxy.bypass_mac), ['aa:bb:cc:00:00:01']);
  assert.equal(store.arp.enabled, '0');
  assert.deepEqual(plain(store.arp.client), ['aa:bb:cc:00:00:02']);
  assert.deepEqual(plain(execs), [['/etc/init.d/meow-arp', ['restart']]]);
});

test('Save unsets bypass_mac when nothing is ticked and skips the ARP restart', async () => {
  const { view, store, writes, execs } = load({ ...base, tproxy: { enabled: '1', bypass_mac: 'aa:bb:cc:00:00:01' } });
  view.render([null, null, hints, leases]);
  view.bypassChecks['aa:bb:cc:00:00:01'].checked = false;
  await view.handleSaveApply();
  assert.equal(store.tproxy.bypass_mac, undefined);
  assert.ok(writes.some(w => w[0] === 'unset' && w[2] === 'bypass_mac'));
  assert.equal(execs.length, 0);
});

test('host hints are limited to LAN clients; leases and selected MACs always stay', () => {
  const { view } = load(base);
  const noisy = {
    '00:00:00:00:00:00': { ipaddrs: [], ip6addrs: ['fe80::1'] },
    '0A:C3:EB:92:9A:FC': { ipaddrs: [], ip6addrs: ['fe80::2'] },
    '46:1C:00:8D:E5:73': { ipaddrs: ['192.168.0.117'] },
    '08:B3:39:91:76:AE': { ipaddrs: ['192.168.1.135'], ip6addrs: ['fd3d::1'] },
    '02:00:00:00:00:07': { ipaddrs: ['192.168.0.7', '192.168.1.7'] },
    'D4:0D:AB:8F:CB:81': { name: 'OpenWrt.lan', ipaddrs: ['192.168.1.1'] }
  };
  const lease = { dhcp_leases: [{ macaddr: '86:de:a8:74:2a:43', hostname: '*', ipaddr: '192.168.1.203' }] };
  const rows = plain(view.buildClients(noisy, lease, {}, ['46:1c:00:8d:e5:73'], [], ['192.168.1.1/24']));
  assert.deepEqual(rows.map(r => [r.mac, r.name, r.ip4, r.source]), [
    ['02:00:00:00:00:07', '', ['192.168.1.7'], 'neighbour'],
    ['08:b3:39:91:76:ae', '', ['192.168.1.135'], 'neighbour'],
    ['86:de:a8:74:2a:43', '', ['192.168.1.203'], 'dhcp'],
    ['46:1c:00:8d:e5:73', '', [], 'offline']
  ]);
  // Unknown subnet: any IPv4 qualifies, the all-zero MAC never does.
  const loose = plain(view.buildClients(noisy, {}, {}, [], [], []));
  assert.deepEqual(loose.map(r => r.mac).sort(),
    ['02:00:00:00:00:07', '08:b3:39:91:76:ae', '46:1c:00:8d:e5:73', 'd4:0d:ab:8f:cb:81']);
});

test('without ARP steering only DHCP clients are shown; toggling reveals neighbours', () => {
  const { view } = load({ ...base, tproxy: { enabled: '1', bypass_mac: 'aa:bb:cc:00:00:02' } });
  const tree = view.render([null, null, hints, leases]);
  const rows = tableRows(tree).slice(1);
  const visible = () => rows.filter(r => !(r.attrs.style === 'display: none;' && r.style.display !== '') &&
    r.style.display !== 'none').map(r => r.children[4].children);
  // laptop and nas are neighbour-only; 00:02 stays because it is bypassed.
  assert.deepEqual(plain(visible()), ['aa:bb:cc:00:00:04', 'aa:bb:cc:00:00:02']);
  view.showSteer(true);
  assert.equal(visible().length, 4);
  view.showSteer(false);
  assert.deepEqual(plain(visible()), ['aa:bb:cc:00:00:04', 'aa:bb:cc:00:00:02']);
});

test('no DHCP clients shows a hint to enable ARP steering', () => {
  const { view } = load(base);
  const tree = view.render([null, null, hints, {}]);
  const body = tableRows(tree);
  assert.equal(body.length, 5);
  assert.match(text(body[1]), /No DHCP clients/);
  assert.equal(body[1].attrs.style, '');
  view.showSteer(true);
  assert.equal(body[1].style.display, 'none');
});

test('newly bypassed neighbours remain visible when steering is hidden', () => {
  const { view } = load({ ...base, arp: { enabled: '1' } });
  const tree = view.render([null, null, hints, leases]);
  const laptop = tableRows(tree).find(r => r.children[4]?.children === 'aa:bb:cc:00:00:01');
  view.bypassChecks['aa:bb:cc:00:00:01'].checked = true;
  view.showSteer(false);
  assert.notEqual(laptop.style.display, 'none');
  view.bypassChecks['aa:bb:cc:00:00:01'].checked = false;
  view.showSteer(false);
  assert.equal(laptop.style.display, 'none');
});
