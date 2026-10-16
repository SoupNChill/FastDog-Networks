import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, tids, request } from './helpers.js';

test('status page API allow-lists the edge payload and is tenant scoped', async (t) => {
  const f = await fixture(t);
  const a = await f.seed();
  const b = await f.seed(1);
  assert.equal((await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' })).status, 201);
  assert.equal((await a.client.call('/api/hostnames/app.example.test/status')).status, 409, 'pending hosts have no status');
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const status = await a.client.call('/api/hostnames/app.example.test/status');
  assert.equal(status.status, 200);
  assert.equal(status.data.live, true);
  assert.equal(status.data.log_path, undefined);
  assert.equal(status.data.agent.origin_address, undefined);
  assert.equal(status.data.cert.serial, undefined);
  assert.equal(status.data.traffic.file, undefined);
  assert.equal(status.data.verdict.file, undefined);
  assert.equal(status.data.verdict.shadow, true);
  assert.equal(status.data.agent.agent_version, '0.1.2');
  assert.deepEqual(f.calls.at(-1), ['status', tids[0], 'app.example.test']);
  const other = await b.client.call('/api/hostnames/app.example.test/status');
  assert.equal(other.status, 404);
  assert.deepEqual(f.calls.at(-1), ['status', tids[1], 'app.example.test']);
  assert.equal((await b.client.call('/api/hostnames/app.example.test/test', 'POST')).status, 404);
});

test('test-it requires a session and CSRF, strips extra fields, and is rate limited per tenant', async (t) => {
  const f = await fixture(t);
  const a = await f.seed();
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  assert.equal((await request(f.port, '/api/hostnames/app.example.test/test', { method: 'POST' })).status, 401);
  assert.equal((await f.client.call('/api/hostnames/app.example.test/test', 'POST')).status, 401);
  assert.equal((await a.client.call('/api/hostnames/app.example.test/test')).status, 405);
  for (let i = 0; i < 6; i++) {
    const run = await a.client.call('/api/hostnames/app.example.test/test', 'POST');
    assert.equal(run.status, 200);
    assert.equal(run.data.upstream, undefined);
    assert.equal(run.data.status, 200);
  }
  const limited = await a.client.call('/api/hostnames/app.example.test/test', 'POST');
  assert.equal(limited.status, 429);
  f.advance(61000);
  assert.equal((await a.client.call('/api/hostnames/app.example.test/test', 'POST')).status, 200);
});

test('status page is served behind sign-in', async (t) => {
  const f = await fixture(t);
  assert.equal((await request(f.port, '/status')).status, 302);
  const a = await f.seed();
  const page = await a.client.call('/status');
  assert.equal(page.status, 200);
  assert.equal((await request(f.port, '/css/status.css')).status, 200);
  assert.equal((await request(f.port, '/js/status.js')).status, 200);
});
