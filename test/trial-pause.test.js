import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { internalHarness, fakeSecret } from './helpers/internal.js';
import { tenants } from './helpers/fixtures.js';
import { tempDir } from './helpers/temp-dir.js';
import { expectError, jsonRequest, listen } from './helpers/http.js';
import { createClaims } from '../src/internal/claims.js';
import { createPausedHosts, servePaused, upgradeUrl, pausedPage } from '../src/edge/paused-hosts.js';

const tenantPath = (tid, action) => `/internal/v1/tenants/${tid}/${action}`;
const files = ['tenant_hostnames.json', 'agent-credentials.json', 'tunnel_hosts.json'];

test('pause and unpause require portal authentication, a valid tenant and POST', async (t) => {
  const h = await internalHarness(t);
  for (const action of ['pause', 'unpause']) {
    for (const headers of [{}, { 'x-fastdog-portal-key': h.agentToken }, { 'x-fastdog-portal-key': fakeSecret() }]) {
      expectError(await jsonRequest(h.server, tenantPath(tenants[0], action), { method: 'POST', headers }), 401, 'unauthorized');
    }
    for (const tid of ['invalid', tenants[0].toUpperCase(), `${tenants[0]}a`]) expectError(await h.request(tenantPath(tid, action), { method: 'POST' }), 400, 'invalid_tenant');
    expectError(await h.request(tenantPath(tenants[0], action)), 405, 'method_not_allowed');
    assert.equal(h.logs.at(-1)[0].route, `/internal/v1/tenants/:tid/${action}`);
  }
});

test('pause is a tenant flag only: claims, credentials and tunnels stay byte-identical, no tunnel closes, TLS ask stays true', async (t) => {
  const h = await internalHarness(t);
  await h.activate(tenants[0], 'one.example.test');
  await h.activate(tenants[0], 'two.example.test');
  await h.activate(tenants[1], 'other.example.test');
  await h.create(tenants[0], 'pending.example.test');
  let changes = 0;
  h.server.on('routesChanged', () => changes++);
  const snapshot = () => files.map((file) => readFileSync(join(h.dataDir, file), 'utf8'));
  const before = snapshot();
  const pause = () => h.request(tenantPath(tenants[0], 'pause'), { method: 'POST' });
  const unpause = () => h.request(tenantPath(tenants[0], 'unpause'), { method: 'POST' });
  assert.deepEqual((await pause()).body, { tenant_id: tenants[0], paused: true, changed: true, hostnames: 2 });
  assert.deepEqual((await pause()).body, { tenant_id: tenants[0], paused: true, changed: false, hostnames: 2 });
  assert.equal(changes, 1);
  assert.deepEqual(Object.keys(JSON.parse(readFileSync(join(h.dataDir, 'paused_tenants.json'), 'utf8')).tenants), [tenants[0]]);
  assert.deepEqual(snapshot(), before);
  assert.deepEqual(h.closed, []);
  const claims = createClaims(h, () => {});
  for (const host of ['one.example.test', 'two.example.test', 'other.example.test']) {
    assert.equal(claims.ask(host), true);
    assert.equal((await h.request(`/tls/ask?domain=${host}`)).status, 200);
  }
  assert.equal((await h.request(`/internal/v1/tenants/${tenants[0]}/hostnames/one.example.test`)).body.status, 'active');
  assert.deepEqual((await unpause()).body, { tenant_id: tenants[0], paused: false, changed: true, hostnames: 2 });
  assert.deepEqual((await unpause()).body, { tenant_id: tenants[0], paused: false, changed: false, hostnames: 2 });
  assert.equal(changes, 2);
  assert.deepEqual(snapshot(), before);
  assert.deepEqual(h.closed, []);
  assert.deepEqual(JSON.parse(readFileSync(join(h.dataDir, 'paused_tenants.json'), 'utf8')), { tenants: {} });
});

test('paused hosts: active claims of paused tenants only, including hosts verified while paused', async (t) => {
  const h = await internalHarness(t);
  await h.activate(tenants[0], 'one.example.test');
  await h.activate(tenants[1], 'other.example.test');
  const paused = createPausedHosts({ dataDir: h.dataDir, ttlMs: 0, warn: () => {} });
  t.after(() => paused.stop());
  assert.equal(paused.isPaused('one.example.test'), false);
  await h.request(tenantPath(tenants[0], 'pause'), { method: 'POST' });
  // Lookups never rebuild: cached until invalidated (routesChanged) or the timer runs.
  assert.equal(paused.isPaused('one.example.test'), false);
  paused.invalidate();
  assert.equal(paused.isPaused('one.example.test'), true);
  assert.equal(paused.isPaused('ONE.example.test:443'), true);
  assert.equal(paused.isPaused('other.example.test'), false);
  await h.activate(tenants[0], 'late.example.test');
  paused.invalidate();
  assert.equal(paused.isPaused('late.example.test'), true);
  await h.request(tenantPath(tenants[0], 'unpause'), { method: 'POST' });
  paused.invalidate();
  assert.equal(paused.isPaused('one.example.test'), false);
});

test('paused hosts are built at creation and rebuilt by the background timer until stopped', async (t) => {
  const h = await internalHarness(t);
  await h.activate(tenants[0], 'one.example.test');
  await h.request(tenantPath(tenants[0], 'pause'), { method: 'POST' });
  const paused = createPausedHosts({ dataDir: h.dataDir, ttlMs: 10, warn: () => {} });
  t.after(() => paused.stop());
  assert.equal(paused.isPaused('one.example.test'), true, 'built at creation');
  await h.request(tenantPath(tenants[0], 'unpause'), { method: 'POST' });
  const until = async (expected) => {
    for (let i = 0; i < 200 && paused.isPaused('one.example.test') !== expected; i++) await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(paused.isPaused('one.example.test'), expected);
  };
  await until(false);
  paused.stop();
  await h.request(tenantPath(tenants[0], 'pause'), { method: 'POST' });
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(paused.isPaused('one.example.test'), false, 'no rebuilds after stop');
});

test('paused hosts fail open: unreadable state keeps the last good set, starts empty and never throws', async (t) => {
  const h = await internalHarness(t);
  await h.activate(tenants[0], 'one.example.test');
  const warnings = [];
  const file = join(h.dataDir, 'paused_tenants.json');
  writeFileSync(file, '{not json');
  const paused = createPausedHosts({ dataDir: h.dataDir, ttlMs: 0, warn: (message) => warnings.push(message) });
  t.after(() => paused.stop());
  assert.equal(paused.isPaused('one.example.test'), false);
  writeFileSync(file, JSON.stringify({ tenants: { [tenants[0]]: { at: '2026-10-19T00:00:00.000Z' } } }));
  paused.invalidate();
  assert.equal(paused.isPaused('one.example.test'), true);
  for (const bad of ['{not json', '[]', JSON.stringify({ tenants: [] })]) {
    writeFileSync(file, bad);
    paused.invalidate();
    assert.equal(paused.isPaused('one.example.test'), true);
  }
  writeFileSync(join(h.dataDir, 'tenant_hostnames.json'), '{"oops":');
  writeFileSync(file, JSON.stringify({ tenants: { [tenants[0]]: {} } }));
  paused.invalidate();
  assert.equal(paused.isPaused('one.example.test'), true);
  for (const value of [undefined, null, 42, {}, ['x']]) assert.equal(paused.isPaused(value), false);
  assert.equal(warnings.length, 2, 'one warning per failure streak');
  assert.ok(warnings.every((w) => !w.includes('example.test')));
  assert.equal(paused.isPaused({ toString() { throw new Error('host'); } }), false);
  // Claims are still unreadable here: startup is empty and a throwing logger never escapes a rebuild.
  const throwing = createPausedHosts({ dataDir: h.dataDir, ttlMs: 0, warn: () => { throw new Error('warn'); } });
  assert.doesNotThrow(() => throwing.invalidate());
  assert.equal(throwing.isPaused('one.example.test'), false);
});

async function gate(t, options) {
  const proxied = [];
  const server = http.createServer((req, res) => {
    if (servePaused(req, res, { resolved: { kind: req.headers['x-kind'] }, tunnelHost: req.headers['x-tunnel-host'] === '1', ...options })) return;
    proxied.push(req.headers.host);
    res.end('proxied');
  });
  await listen(t, server);
  const get = (host, headers = {}) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: server.address().port, path: '/', headers: { host, ...headers } }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    }).on('error', reject);
  });
  return { get, proxied };
}

test('paused tunnel hosts get the 503 paused page; unpaused, static and default routes proxy', async (t) => {
  const isPaused = (host) => host === 'paused.example.test';
  const { get, proxied } = await gate(t, { isPaused, link: upgradeUrl('https://plans.example.test/choose?a=1&b="x"') });
  const page = await get('paused.example.test', { 'x-kind': 'tunnel' });
  assert.equal(page.status, 503);
  assert.equal(page.headers['retry-after'], '3600');
  assert.equal(page.headers['cache-control'], 'no-store');
  assert.equal(page.headers['x-robots-tag'], 'noindex');
  assert.equal(page.headers['x-fastdog-paused'], '1');
  assert.match(page.headers['content-type'], /^text\/html/);
  assert.match(page.body, /<title>Site paused<\/title>/);
  assert.match(page.body, /This site is paused because its free trial has ended\. The site owner can choose a plan to bring it back\. Nothing has been deleted\./);
  assert.match(page.body, /<a href="https:\/\/plans\.example\.test\/choose\?a=1&amp;b=%22x%22">Site owner\? Choose a plan<\/a>/);
  // A tunnel host whose agent is offline is still the customer's route.
  assert.equal((await get('paused.example.test', { 'x-kind': 'default', 'x-tunnel-host': '1' })).status, 503);
  for (const [host, kind] of [['open.example.test', 'tunnel'], ['paused.example.test', 'static'], ['paused.example.test', 'default']]) {
    const response = await get(host, { 'x-kind': kind });
    assert.equal(response.status, 200);
    assert.equal(response.body, 'proxied');
    assert.equal(response.headers['x-fastdog-paused'], undefined);
  }
  assert.equal(proxied.length, 3);
});

test('edge catch-all serves the paused page for a paused customer host and proxies the rest', async (t) => {
  const dir = tempDir(t);
  const upstream = http.createServer((req, res) => res.end(`proxied ${req.headers.host}`));
  await listen(t, upstream);
  const upstreamUrl = `http://127.0.0.1:${upstream.address().port}`;
  const write = (name, value) => writeFileSync(join(dir, name), JSON.stringify(value));
  write('routes.json', { routes: { 'static.example.test': upstreamUrl } });
  write('tunnel_hosts.json', ['paused.example.test', 'open.example.test', 'static.example.test']);
  write('tenant_hostnames.json', [['paused.example.test', tenants[0]], ['open.example.test', tenants[1]], ['static.example.test', tenants[0]]]
    .map(([hostname, tenant_id]) => ({ tenant_id, hostname, status: 'active' })));
  write('paused_tenants.json', { tenants: { [tenants[0]]: { at: '2026-10-19T00:00:00.000Z' } } });
  Object.assign(process.env, { NODE_ENV: 'test', AGENT_TOKEN: fakeSecret(), DATA_DIR: dir, ROUTES_FILE: join(dir, 'routes.json'),
    DEFAULT_UPSTREAM: upstreamUrl, PAUSED_UPGRADE_URL: 'https://plans.example.test/' });
  const edge = await import('../src/edge/server.js');
  await listen(t, edge.server);
  const get = async (host) => {
    const res = await new Promise((resolve, reject) => http.get({ host: '127.0.0.1', port: edge.server.address().port, path: '/', headers: { host } }, resolve).on('error', reject));
    let body = '';
    for await (const chunk of res) body += chunk;
    return { status: res.statusCode, headers: res.headers, body };
  };
  const paused = await get('paused.example.test');
  assert.equal(paused.status, 503);
  assert.equal(paused.headers['x-fastdog-paused'], '1');
  assert.match(paused.body, /href="https:\/\/plans\.example\.test\/">Site owner\? Choose a plan/);
  for (const host of ['open.example.test', 'static.example.test', 'unknown.example.test']) {
    const response = await get(host);
    assert.equal(response.status, 200, host);
    assert.match(response.body, /^proxied /, host);
    assert.equal(response.headers['x-fastdog-paused'], undefined);
  }
});

test('paused page link only for a valid https URL; a throwing lookup proxies', async (t) => {
  for (const value of [undefined, '', 'http://plans.example.test/', 'javascript:alert(1)', 'not a url', 'https://user:pw@plans.example.test/']) {
    assert.equal(upgradeUrl(value), null);
    assert.ok(!pausedPage(upgradeUrl(value)).includes('<a '));
  }
  const { get } = await gate(t, { isPaused: () => { throw new Error('boom'); }, link: null });
  assert.equal((await get('paused.example.test', { 'x-kind': 'tunnel' })).body, 'proxied');
});
