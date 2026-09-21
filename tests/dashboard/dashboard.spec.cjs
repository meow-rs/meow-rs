const { test: base, expect } = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '../../crates/meow-api/static/index.html'), 'utf8');
const origin = 'http://dashboard.test';

// Load the actual shipped HTML in Chromium. All controller traffic is isolated
// from the user's running proxy and captured for request-contract assertions.
const test = base.extend({
  dashboard: async ({ page }, use) => {
    const state = {
      mode: 'rule', groups: [], subscriptions: [], rules: [], requests: [],
      sockets: [], closedSockets: [], errors: [], failures: new Map(),
      proxies: { DIRECT: {}, REJECT: {}, 'Node A': {}, 'Node B': {} },
    };
    page.on('pageerror', error => state.errors.push(error.message));
    await page.routeWebSocket(`${origin.replace('http:', 'ws:')}/traffic*`, socket => {
      state.sockets.push(socket);
      socket.onClose(() => state.closedSockets.push(socket));
      socket.send(JSON.stringify({ up: 1024, down: 2048 }));
    });
    await page.route('**/*', async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin !== origin) throw new Error(`Unexpected external request: ${url.origin}`);
      if (url.pathname === '/ui') return route.fulfill({ contentType: 'text/html', body: html });
      const method = request.method();
      const body = request.postDataJSON();
      const endpoint = url.pathname;
      state.requests.push({ endpoint, method, body, headers: request.headers() });
      const fail = state.failures.get(endpoint);
      if (fail) return route.fulfill({ status: fail, body: 'Controller request rejected' });
      let result;
      if (endpoint === '/configs') {
        if (method === 'PATCH') state.mode = body.mode;
        result = { mode: state.mode, 'mixed-port': 7890, 'external-controller': '127.0.0.1:9090' };
      } else if (endpoint === '/connections') result = { connections: [{ id: 'one' }] };
      else if (endpoint === '/traffic') {
        // Never produce a finite JSON response: this catches the original
        // dashboard regression even if it is reintroduced alongside WebSockets.
        return;
      } else if (endpoint === '/proxies') result = { proxies: state.proxies };
      else if (endpoint === '/api/proxy-groups') {
        if (method === 'POST') state.groups.push({ ...body, now: body.proxies[0] });
        result = state.groups;
      } else if (endpoint.startsWith('/api/proxy-groups/')) {
        const selecting = endpoint.endsWith('/select');
        const name = decodeURIComponent(endpoint.slice('/api/proxy-groups/'.length).replace(/\/select$/, ''));
        if (selecting) state.groups.find(group => group.name === name).now = body.name;
        else state.groups = state.groups.filter(group => group.name !== name);
      } else if (endpoint === '/api/subscriptions') {
        if (method === 'POST') {
          const sub = { ...body, proxy_count: 2, group_count: 1, rule_count: 1, last_updated: 1 };
          state.subscriptions.push(sub);
          result = sub;
        } else result = state.subscriptions;
      } else if (endpoint.startsWith('/api/subscriptions/')) {
        const name = decodeURIComponent(endpoint.slice('/api/subscriptions/'.length).replace(/\/refresh$/, ''));
        if (method === 'DELETE') state.subscriptions = state.subscriptions.filter(sub => sub.name !== name);
        else result = { proxy_count: 2, group_count: 1, rule_count: 1 };
      } else if (endpoint === '/rules') {
        if (method === 'POST') state.rules = body.rules.map(raw => {
          const [type, ...parts] = raw.split(',');
          const proxy = parts.pop();
          return { type, payload: parts.join(','), proxy };
        });
        result = { rules: state.rules };
      } else if (endpoint === '/rules/reorder') {
        const [rule] = state.rules.splice(body.from, 1);
        state.rules.splice(body.to, 0, rule);
      } else if (endpoint.startsWith('/rules/') && method === 'DELETE') {
        state.rules.splice(Number(endpoint.slice('/rules/'.length)), 1);
      } else if (endpoint !== '/api/config/save') throw new Error(`Unhandled endpoint: ${method} ${endpoint}`);
      return result === undefined ? route.fulfill({ status: 204 }) : route.fulfill({ json: result });
    });
    state.open = () => page.goto(`${origin}/ui`);
    state.tab = name => page.locator('nav').getByRole('button', { name, exact: true }).click();
    state.mutations = () => state.requests.filter(request => request.method !== 'GET');
    await use(state);
    expect(state.errors).toEqual([]);
  },
});

test('overview renders while HTTP traffic never ends and keeps one live socket', async ({ page, dashboard: d }) => {
  await d.open();
  await expect(page.locator('#listeners-info')).toContainText('7890');
  await expect(page.locator('#mode-selector .active')).toHaveText('Rule');
  await expect(page.locator('#stat-connections')).toHaveText('1');
  await expect(page.locator('#stat-download')).toHaveText('2.0 KB');
  d.sockets[0].send(JSON.stringify({ up: 4096, down: 8192 }));
  await expect(page.locator('#stat-upload')).toHaveText('4.0 KB');
  await expect.poll(() => d.requests.filter(r => r.endpoint === '/connections').length).toBeGreaterThan(1);
  expect(d.sockets).toHaveLength(1);
  expect(d.requests.filter(r => r.endpoint === '/traffic')).toHaveLength(0);
});

test('all tabs load their empty states and mode changes reach the controller', async ({ page, dashboard: d }) => {
  await d.open();
  for (const [tab, empty] of [['Proxies', '#proxy-selector-empty'], ['Subscriptions', '#sub-empty'], ['Proxy Groups', '#group-empty'], ['Rules', '#rules-empty']]) {
    await d.tab(tab);
    await expect(page.locator(empty)).toBeVisible();
    await expect(page.locator('main > div:visible')).toHaveCount(1);
  }
  await d.tab('Overview');
  await page.getByRole('button', { name: 'Global', exact: true }).click();
  await expect(page.locator('#mode-selector .active')).toHaveText('Global');
  expect(d.mutations()).toContainEqual(expect.objectContaining({ endpoint: '/configs', method: 'PATCH', body: { mode: 'global' } }));
});

test('API errors are visible and updating the secret authenticates HTTP and WebSocket', async ({ page, dashboard: d }) => {
  d.failures.set('/configs', 401);
  await d.open();
  await expect(page.locator('#toast')).toContainText('Failed to load overview: Controller request rejected');
  d.failures.clear();
  const secret = 'test & ? token';
  await page.locator('#api-secret').fill(secret);
  await page.locator('#api-secret').blur();
  await expect(page.locator('#listeners-info')).toContainText('7890');
  await expect.poll(() => d.sockets.length).toBe(2);
  expect(new URL(d.sockets[1].url()).searchParams.get('token')).toBe(secret);
  expect(d.requests.filter(r => r.endpoint === '/configs').at(-1).headers.authorization).toBe(`Bearer ${secret}`);
  await expect.poll(() => d.closedSockets.length).toBe(1);
  await page.reload();
  await expect(page.locator('#api-secret')).toHaveValue(secret);
});

test('a dropped traffic socket reconnects and resumes updates', async ({ page, dashboard: d }) => {
  await d.open();
  await expect(page.locator('#stat-upload')).toHaveText('1.0 KB');
  d.sockets[0].close({ code: 1011, reason: 'test disconnect' });
  await expect.poll(() => d.sockets.length).toBe(2);
  d.sockets[1].send(JSON.stringify({ up: 16384, down: 0 }));
  await expect(page.locator('#stat-upload')).toHaveText('16.0 KB');
});

test('proxy names render as text and selection uses encoded group names', async ({ page, dashboard: d }) => {
  const name = 'Group / " <b>special</b>';
  const proxy = '<img src=x onerror="throw Error(1)">';
  d.groups.push({ name, type: 'select', proxies: ['Node A', proxy], now: 'Node A' });
  await d.open();
  await d.tab('Proxies');
  await expect(page.locator('.group-header strong')).toHaveText(name);
  await expect(page.locator('#proxy-groups-selector img, #proxy-groups-selector b')).toHaveCount(0);
  await page.locator('.proxy-item').filter({ hasText: proxy }).click();
  await expect(page.locator('.proxy-item.selected')).toHaveText(proxy);
  expect(d.mutations()).toContainEqual(expect.objectContaining({ endpoint: `/api/proxy-groups/${encodeURIComponent(name)}/select`, method: 'PUT', body: { name: proxy } }));
});

test('subscriptions validate inputs, add, refresh, and confirm deletion', async ({ page, dashboard: d }) => {
  await d.open();
  await d.tab('Subscriptions');
  await page.locator('#tab-subscriptions').getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.locator('#toast')).toHaveText('Name and URL required');
  expect(d.mutations()).toHaveLength(0);
  await page.locator('#sub-name').fill('Test / Feed');
  await page.locator('#sub-url').fill('https://example.test/sub');
  await page.locator('#sub-interval').fill('3600');
  await page.locator('#tab-subscriptions').getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.locator('#sub-list tr')).toHaveCount(1);
  expect(d.mutations()[0].body).toEqual({ name: 'Test / Feed', url: 'https://example.test/sub', interval: 3600 });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.locator('#toast')).toContainText('Refreshed: 2 proxies');
  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#sub-list').getByRole('button', { name: 'Delete' }).click();
  expect(d.mutations().filter(r => r.method === 'DELETE')).toHaveLength(0);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#sub-list').getByRole('button', { name: 'Delete' }).click();
  await expect(page.locator('#sub-empty')).toBeVisible();
  expect(d.mutations().at(-1).endpoint).toBe('/api/subscriptions/Test%20%2F%20Feed');
});

test('groups validate members, create, and delete through the UI', async ({ page, dashboard: d }) => {
  await d.open();
  await d.tab('Proxy Groups');
  await page.locator('#grp-name').fill('Test Group');
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(page.locator('#toast')).toHaveText('Select at least one proxy');
  expect(d.mutations()).toHaveLength(0);
  await page.locator('#grp-proxies').selectOption(['Node A', 'Node B']);
  await page.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(page.locator('#group-list')).toContainText('Test Group');
  expect(d.mutations()[0].body).toEqual({ name: 'Test Group', type: 'select', proxies: ['Node A', 'Node B'] });
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#group-list').getByRole('button', { name: 'Delete' }).click();
  await expect(page.locator('#group-empty')).toBeVisible();
});

test('rules add MATCH without payload, filter, reorder, and delete original indices', async ({ page, dashboard: d }) => {
  d.rules = [{ type: 'DOMAIN', payload: 'example.test', proxy: 'DIRECT' }, { type: 'DOMAIN', payload: 'other.test', proxy: 'REJECT' }];
  await d.open();
  await d.tab('Rules');
  await expect(page.locator('#rules-list .rule-row')).toHaveCount(2);
  await page.locator('#rule-type').selectOption('MATCH');
  await page.locator('#rule-target').selectOption('DIRECT');
  await page.locator('#tab-rules').getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.locator('#rules-list .rule-row')).toHaveCount(3);
  expect(d.mutations()[0].body.rules).toEqual(['DOMAIN,example.test,DIRECT', 'DOMAIN,other.test,REJECT', 'MATCH,DIRECT']);
  await page.locator('.rule-row').nth(2).dragTo(page.locator('.rule-row').nth(0));
  await expect(page.locator('.rule-row').first()).toContainText('MATCH,DIRECT');
  expect(d.mutations()).toContainEqual(expect.objectContaining({ endpoint: '/rules/reorder', body: { from: 2, to: 0 } }));
  await page.locator('#rules-search').fill('OTHER.TEST');
  await expect(page.locator('.rule-row')).toHaveCount(1);
  await page.locator('.rule-row button').click();
  await expect(page.locator('#rules-count')).toHaveText('2');
  expect(d.mutations().at(-1).endpoint).toBe('/rules/2');
});

test('failed mutations preserve form values and save reports success and failure', async ({ page, dashboard: d }) => {
  await d.open();
  await d.tab('Subscriptions');
  d.failures.set('/api/subscriptions', 500);
  await page.locator('#sub-name').fill('Retry me');
  await page.locator('#sub-url').fill('https://example.test/sub');
  await page.locator('#tab-subscriptions').getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.locator('#toast')).toContainText('Failed: Controller request rejected');
  await expect(page.locator('#sub-name')).toHaveValue('Retry me');
  await page.getByRole('button', { name: 'Save Config' }).click();
  await expect(page.locator('#toast')).toHaveText('Config saved to disk');
  d.failures.set('/api/config/save', 500);
  await page.getByRole('button', { name: 'Save Config' }).click();
  await expect(page.locator('#toast')).toContainText('Save failed: Controller request rejected');
});
