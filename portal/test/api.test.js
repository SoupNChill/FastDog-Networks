import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { normalizeHostname, isReserved } from '../src/hostname.js';
import { fixture, tids, fakeSecret, request, origin } from './helpers.js';

test('normalization handles boundary lengths, IDN, case and unsafe syntax', () => {
  for (const host of ['App.Example.COM', ' app.example.com. ']) assert.equal(normalizeHostname(host), 'app.example.com');
  assert.equal(normalizeHostname('bücher.example.com'), 'xn--bcher-kva.example.com');
  for (const host of [`${'a'.repeat(63)}.example.com`, `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(49)}.example.com`]) assert.equal(normalizeHostname(host), host);
  for (const host of ['*.example.com', 'a*.example.com', '127.0.0.1', 'app.example.com:80', 'app.example.com/path', '-a.example.com', 'a-.example.com', 'a..example.com', 'a.example.c', 'app.example.com..', 'app .example.com', 'a\0.example.com', `${'a'.repeat(64)}.example.com`, null, 'http://app.example.com', 'app%2eexample.com']) {
    assert.throws(() => normalizeHostname(host), { code: 'invalid_hostname' });
  }
  assert.ok(isReserved('x.reserved.example.com', ['reserved.example.com']));
  assert.equal(isReserved('notreserved.example.com', ['reserved.example.com']), false);
});

test('hostname operations derive tenant from session and never replay credentials', async (t) => {
  const f = await fixture(t);
  const a = await f.seed();
  const b = await f.seed(1);
  const host = 'app.example.com';
  const path = `/api/hostnames/${host}`;
  assert.equal((await a.client.call('/api/hostnames', 'POST', { hostname: 'App.Example.COM.', tenant_id: tids[1], hostname_limit: 1000 })).status, 201);
  assert.deepEqual(f.calls[0], ['create', tids[0], host, 3]);
  assert.equal((await b.client.call(`/api/hostnames?tenant_id=${tids[0]}`)).data.hostnames.length, 0);
  for (const [method, suffix] of [['GET', ''], ['POST', '/verify'], ['POST', '/rotate'], ['GET', '/agent'], ['DELETE', '']]) {
    const result = await b.client.call(`${path}${suffix}?tenant_id=${tids[0]}`, method, method === 'GET' ? undefined : { tenant_id: tids[0] }, { 'x-tenant-id': tids[0] });
    assert.equal(result.status, 404);
    assert.deepEqual(result.data, { error: 'hostname_not_found' });
    assert.equal(f.calls.at(-1)[1], tids[1]);
  }
  const verified = await a.client.call(`${path}/verify`, 'POST');
  assert.ok(verified.data.credential.token);
  assert.equal((await a.client.call(`${path}/verify`, 'POST')).data.credential, undefined);
  const stored = f.records.get(`${tids[0]}:${host}`);
  stored.credential = verified.data.credential;
  stored.localUpstream = 'http://127.0.0.1:1';
  const detail = await a.client.call(path);
  assert.equal(detail.data.credential, undefined);
  assert.equal(detail.data.dns, undefined);
  assert.equal(detail.data.localUpstream, undefined);
  assert.ok(!(await a.client.call('/api/hostnames')).text.includes(verified.data.credential.token));
  for (const file of readdirSync(f.dataDir).filter((name) => name.endsWith('.json'))) assert.ok(!readFileSync(join(f.dataDir, file), 'utf8').includes(verified.data.credential.token));
  const rotated = await a.client.call(`${path}/rotate`, 'POST');
  assert.notEqual(rotated.data.credential.token, verified.data.credential.token);
  assert.equal((await a.client.call(`${path}/agent`)).status, 200);
  assert.equal((await a.client.call(path, 'DELETE')).status, 200);
  assert.equal((await a.client.call(path)).status, 404);
});

test('domain requests cap open records, isolate tenants and write private outbox notifications', async (t) => {
  const f = await fixture(t);
  const a = await f.seed();
  const b = await f.seed(1);
  for (let i = 0; i < 3; i++) {
    const response = await a.client.call('/api/domain-requests', 'POST', { name: `name${i}.example.com`, quoted_price: '12.34', tenant_id: tids[1], status: 'registered' });
    assert.equal(response.status, 201);
    assert.equal(response.data.tenant_id, tids[0]);
    assert.equal(response.data.status, 'requested');
  }
  assert.equal((await a.client.call('/api/domain-requests', 'POST', { name: 'extra.example.com' })).status, 400);
  assert.equal((await b.client.call('/api/domain-requests')).data.requests.length, 0);
  assert.equal((await a.client.call('/api/domain-requests')).data.requests.length, 3);
  const entries = f.store.read('domain_requests');
  entries[0].status = 'registered';
  f.store.write('domain_requests', entries);
  assert.equal((await a.client.call('/api/domain-requests', 'POST', { name: 'extra.example.com' })).status, 201);
  assert.equal((await b.client.call('/api/plan')).data.hostname_limit, 4);
  const files = readdirSync(join(f.dataDir, 'outbox'));
  assert.equal(files.length, 4);
  for (const file of files) assert.equal(statSync(join(f.dataDir, 'outbox', file)).mode & 0o777, 0o600);
});

test('signup, login account, login IP and search limits use the injected clock', async (t) => {
  const f = await fixture(t);
  for (let i = 0; i < 3; i++) assert.equal((await f.client.call('/api/signup', 'POST', {})).status, 200);
  const limited = await f.client.call('/api/signup', 'POST', {});
  assert.equal(limited.status, 429);
  assert.equal(limited.data.retry_after, 3600);
  assert.equal(limited.headers['retry-after'], '3600');
  const a = await f.seed();
  for (const email of [a.user.email, 'absent@example.com']) {
    for (let i = 0; i < 5; i++) assert.deepEqual((await f.client.call('/api/login', 'POST', { email, password: fakeSecret() })).data, { error: 'unauthorized' });
    assert.equal((await f.client.call('/api/login', 'POST', { email, password: fakeSecret() })).status, 429);
  }
  // The exhausted account attempts above also count against the shared IP.
  for (let i = 0; i < 8; i++) assert.equal((await f.client.call('/api/login', 'POST', { email: `absent${i}@example.com`, password: fakeSecret() })).status, 401);
  assert.equal((await f.client.call('/api/login', 'POST', { email: 'last@example.com', password: fakeSecret() })).status, 429);
  f.advance(900000);
  assert.equal((await f.client.call('/api/login', 'POST', { email: 'last@example.com', password: fakeSecret() })).status, 401);
  assert.equal((await f.client.call('/api/domains/search?q=example.test')).status, 401);
  for (let i = 0; i < 30; i++) assert.equal((await a.client.call('/api/domains/search?q=example.com')).status, 200);
  assert.equal((await a.client.call('/api/domains/search?q=example.com')).status, 429);
  f.advance(600000);
  assert.equal((await a.client.call('/api/domains/search?q=example.com')).status, 200);
});

test('hostname verification and rotation are limited without extra edge calls', async (t) => {
  const f = await fixture(t);
  const a = await f.seed();
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.com' });
  for (let i = 0; i < 6; i++) assert.equal((await a.client.call('/api/hostnames/app.example.com/verify', 'POST')).status, 200);
  assert.equal((await a.client.call('/api/hostnames/app.example.com/verify', 'POST')).status, 429);
  assert.equal(f.calls.filter(([op]) => op === 'verify').length, 6);
  for (let i = 0; i < 5; i++) assert.equal((await a.client.call('/api/hostnames/app.example.com/rotate', 'POST')).status, 200);
  assert.equal((await a.client.call('/api/hostnames/app.example.com/rotate', 'POST')).status, 429);
  assert.equal(f.calls.filter(([op]) => op === 'rotate').length, 5);
  assert.ok(f.store.read('rate_limits')[`rotate:${tids[0]}:app.example.com`]);
  f.advance(86400000);
  assert.equal((await a.client.call('/api/hostnames/app.example.com/rotate', 'POST')).status, 200);
});

test('malformed bodies, methods, untrusted forwarding and logger expose no request details', async (t) => {
  const logs = [];
  const f = await fixture(t, { logger: (entry) => logs.push(entry) });
  const { client } = await f.seed();
  const headers = { cookie: client.cookie, origin, 'x-fd-csrf': client.csrf };
  assert.equal((await request(f.port, '/api/hostnames', { method: 'POST', headers, body: '{' })).status, 400);
  assert.equal((await request(f.port, '/api/hostnames', { method: 'POST', headers, body: '[]' })).status, 400);
  const huge = await request(f.port, '/api/hostnames', { method: 'POST', headers, body: JSON.stringify({ value: 'x'.repeat(17000) }) });
  assert.equal(huge.status, 413);
  assert.equal((await client.call('/api/plan', 'POST')).status, 405);
  assert.equal((await client.call('/api/no-route')).status, 404);
  await client.call('/api/hostnames/app.example.com/agent?token=secret-query');
  await client.call('/api/domains/search?q=example.com', 'GET', undefined, { 'x-forwarded-for': '192.0.2.1' });
  assert.equal(f.searches.at(-1)[1], '127.0.0.1');
  assert.ok(!JSON.stringify(logs).includes('secret-query'));
  assert.ok(!JSON.stringify(logs).includes('app.example.com'));
  assert.ok(!JSON.stringify(logs).includes(client.cookie));
});

test('concurrent domain requests cannot exceed the open-request cap', async (t) => {
  const f = await fixture(t);
  const { client } = await f.seed();
  const results = await Promise.all(Array.from({ length: 6 }, (_, i) => client.call('/api/domain-requests', 'POST', { name: `request${i}.example.com` })));
  assert.equal(results.filter((result) => result.status === 201).length, 3);
  assert.equal(f.store.read('domain_requests').length, 3);
});
