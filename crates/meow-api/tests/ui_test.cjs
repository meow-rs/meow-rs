// Run with: node --test crates/meow-api/tests/ui_test.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const html = fs.readFileSync(`${__dirname}/../static/index.html`, 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];

function dashboard(protocol = 'http:') {
  const elements = new Map();
  const events = {};
  const sockets = [];
  const requests = [];
  const timers = new Map();
  const storage = new Map();
  let timerId = 0;
  const element = id => {
    if (!elements.has(id)) elements.set(id, {
      textContent: '', innerHTML: '', value: '',
      classList: { contains: () => false },
      addEventListener(name, callback) { this[name] = callback; },
    });
    return elements.get(id);
  };
  class WebSocket {
    constructor(url) { this.url = new URL(url); sockets.push(this); }
    close() { this.closed = true; if (this.onclose) this.onclose(); }
  }
  vm.runInNewContext(script, {
    window: { location: { origin: `${protocol}//localhost:9090` },
      addEventListener: (name, callback) => { events[name] = callback; } },
    document: { getElementById: element, querySelectorAll: () => [] },
    localStorage: { getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value) },
    fetch: async url => {
      const path = new URL(url).pathname;
      requests.push(path);
      // A real HTTP traffic body never ends. Overview must not wait on it.
      if (path === '/traffic') return { ok: true, json: () => new Promise(() => {}) };
      return { ok: true, json: async () => path === '/configs'
        ? { mode: 'rule', 'mixed-port': 7890 } : { connections: [{ id: 'test' }] } };
    },
    WebSocket, URL, console,
    setInterval: callback => { events.poll = callback; },
    setTimeout: callback => { timers.set(++timerId, callback); return timerId; },
    clearTimeout: id => timers.delete(id),
  });
  return { element, events, sockets, requests, timers, storage };
}

const settle = () => new Promise(resolve => setImmediate(resolve));

test('overview and polling finish without waiting for the endless traffic body', async () => {
  const ui = dashboard();
  await settle();
  assert.match(ui.element('listeners-info').innerHTML, /7890/);
  assert.equal(ui.element('stat-connections').textContent, 1);
  await ui.events.poll();
  assert.ok(!ui.requests.includes('/traffic'));
});

test('one traffic socket renders multiple samples and reconnects after disconnect', () => {
  const ui = dashboard();
  ui.events.pageshow();
  const socket = ui.sockets[0];
  socket.onmessage({ data: '{"up":1024,"down":2048}' });
  assert.equal(ui.element('stat-upload').textContent, '1.0 KB');
  socket.onmessage({ data: '{"up":3072,"down":4096}' });
  assert.equal(ui.element('stat-download').textContent, '4.0 KB');
  assert.equal(ui.sockets.length, 1);
  socket.close();
  assert.equal(ui.timers.size, 1);
  [...ui.timers.values()][0]();
  assert.equal(ui.sockets.length, 2);
  assert.equal(ui.timers.size, 0);
});

test('changing credentials replaces the socket and preserves secure WebSocket URLs', () => {
  const ui = dashboard('https:');
  ui.events.pageshow();
  const previous = ui.sockets[0];
  ui.element('api-secret').change({ target: { value: 'test & ? token' } });
  assert.equal(previous.closed, true);
  assert.equal(ui.timers.size, 0);
  assert.equal(ui.sockets[1].url.protocol, 'wss:');
  assert.equal(ui.sockets[1].url.searchParams.get('token'), 'test & ? token');
});

test('leaving the page cancels retries; restoring it opens a fresh socket', () => {
  const ui = dashboard();
  ui.events.pageshow();
  ui.sockets[0].close();
  ui.events.pagehide();
  assert.equal(ui.timers.size, 0);
  ui.events.pageshow();
  assert.equal(ui.sockets.length, 2);
  ui.events.pagehide();
  assert.equal(ui.sockets[1].closed, true);
  assert.equal(ui.timers.size, 0);
});
