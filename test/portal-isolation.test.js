import { laneSkip } from './helpers/lanes.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { portalFile, twoAccounts, browser } from './helpers/portal.js';
import { fakeSecret } from './helpers/internal.js';
import { expectRateLimit } from './helpers/http.js';

const skip = laneSkip(existsSync(portalFile), 'lane B not merged: portal app absent');

test('portal derives tenant scope and hostname limit exclusively from each session', { skip }, async (t) => {
  const h = await twoAccounts(t);
  if (!h) return;
  const hosts = ['app.example.com', 'myapp.example.com'];
  for (let i = 0; i < 2; i++) {
    const account = h.accounts[i];
    const other = h.accounts[1 - i];
    h.edge.records.set(account.tenantId, [{ hostname: hosts[i], status: 'active' }]);
    const body = { hostname: hosts[i], tenant_id: other.tenantId, owner: other.tenantId,
      owner_id: other.tenantId, hostname_owner: other.tenantId, hostname_limit: 1000 };
    const headers = { 'x-tenant-id': other.tenantId, 'x-owner-id': other.tenantId, tenant_id: other.tenantId };
    const query = `?tenant_id=${other.tenantId}&owner=${other.tenantId}`;
    const routes = [['GET', '/api/hostnames', 'listHostnames'], ['POST', '/api/hostnames', 'createHostname'],
      ['POST', `/api/hostnames/${hosts[i]}/verify`, 'verifyHostname'],
      ['POST', `/api/hostnames/${hosts[i]}/rotate`, 'rotateCredential'],
      ['GET', `/api/hostnames/${hosts[i]}/agent`, 'getAgent'],
      ['DELETE', `/api/hostnames/${hosts[i]}`, 'deleteHostname']];
    for (const [method, path, edgeMethod] of routes) {
      const start = h.edge.calls.length;
      const result = await account.client.request(path + query, { method, headers, ...(method === 'GET' ? {} : { body }) });
      assert.ok(result.status >= 200 && result.status < 300, `${method} ${path} must use the session scope`);
      const calls = h.edge.calls.slice(start);
      assert.ok(calls.some((call) => call.method === edgeMethod));
      assert.ok(calls.every((call) => call.tenantId === account.tenantId));
      if (edgeMethod === 'createHostname') assert.equal(calls.find((call) => call.method === edgeMethod).hostnameLimit, account.me.tenant.hostname_limit);
      assert.ok(!result.text.includes(other.tenantId));
      if (edgeMethod === 'listHostnames') {
        assert.ok(result.body.hostnames.every((record) => record.hostname === hosts[i]));
        assert.ok(!result.body.hostnames.some((record) => record.hostname === hosts[1 - i])); // exact match: names may be suffixes of each other
      }
    }
  }
  for (let i = 0; i < 2; i++) for (const [method, suffix] of [['POST', '/verify'], ['POST', '/rotate'], ['GET', '/agent'], ['DELETE', '']]) {
    const result = await h.accounts[i].client.request(`/api/hostnames/${hosts[1 - i]}${suffix}`, { method });
    assert.equal(result.status, 404);
    assert.deepEqual(result.body, { error: 'hostname_not_found' });
  }
});

test('session cookies have every required attribute; Origin and CSRF independently reject writes', { skip }, async (t) => {
  const h = await twoAccounts(t);
  if (!h) return;
  const account = h.accounts[0];
  const cookie = account.login.headers['set-cookie']?.find((item) => item.startsWith('__Host-fd_session='));
  assert.ok(cookie);
  for (const attribute of [/;\s*Secure(?:;|$)/i, /;\s*HttpOnly(?:;|$)/i, /;\s*SameSite=Lax(?:;|$)/i, /;\s*Path=\/(?:;|$)/i]) assert.match(cookie, attribute);
  assert.doesNotMatch(cookie, /;\s*Domain=/i);
  const routes = [['POST', '/api/hostnames'], ['POST', '/api/hostnames/app.example.com/verify'],
    ['POST', '/api/hostnames/app.example.com/rotate'], ['DELETE', '/api/hostnames/app.example.com'],
    ['POST', '/api/domain-requests'], ['POST', '/api/logout']];
  for (const [method, path] of routes) for (const headers of [
    { 'x-fd-csrf': '' }, { 'x-fd-csrf': fakeSecret() }, { origin: 'https://other.example.test' }, { origin: '' },
  ]) {
    const count = h.edge.calls.length;
    const result = await account.client.request(path, { method, headers, body: { hostname: 'app.example.com' } });
    assert.equal(result.status, 401); // contract error table has no 403; CSRF/Origin failures are `unauthorized`
    assert.equal(typeof result.body.error, 'string');
    assert.deepEqual(Object.keys(result.body), ['error']);
    assert.equal(h.edge.calls.length, count);
  }
});

test('unknown email and wrong password have identical failures and account login limits recover', { skip }, async (t) => {
  const h = await twoAccounts(t);
  if (!h) return;
  const client = browser(h.server);
  await client.request('/api/me');
  const attempt = (email, headers = {}) => client.request('/api/login', { method: 'POST', headers, body: { email, password: fakeSecret() } });
  const known = await attempt(h.accounts[0].email);
  const unknown = await attempt('unknown@example.test');
  assert.equal(known.status, 401);
  assert.equal(unknown.status, known.status);
  assert.equal(unknown.text, known.text);
  for (let i = 1; i < 5; i++) assert.equal((await attempt(h.accounts[0].email)).status, 401);
  expectRateLimit(await attempt(h.accounts[0].email));
  h.clock.advance(900_001);
  assert.equal((await attempt(h.accounts[0].email)).status, 401);
});

test('login IP limit cannot be bypassed using forwarded client headers', { skip }, async (t) => {
  const h = await twoAccounts(t);
  if (!h) return;
  h.clock.advance(900_001);
  const client = browser(h.server);
  await client.request('/api/me');
  const attempt = (i) => client.request('/api/login', { method: 'POST',
    headers: { 'x-forwarded-for': `192.0.2.${i + 1}`, 'x-real-ip': `198.51.100.${i + 1}` },
    body: { email: `missing-${i}@example.test`, password: fakeSecret() } });
  for (let i = 0; i < 20; i++) assert.equal((await attempt(i)).status, 401);
  expectRateLimit(await attempt(20));
  h.clock.advance(900_001);
  assert.equal((await attempt(21)).status, 401);
});

test('signup is capped at three per hour per IP and verify at six per minute per tenant', { skip }, async (t) => {
  const h = await twoAccounts(t);
  if (!h) return;
  h.clock.advance(3_600_001);
  const client = browser(h.server);
  await client.request('/api/me');
  const signup = (i) => client.request('/api/signup', { method: 'POST',
    body: { email: `signup-${i}@example.test`, password: fakeSecret(), invite_code: fakeSecret() } });
  for (let i = 0; i < 3; i++) assert.notEqual((await signup(i)).status, 429);
  expectRateLimit(await signup(3));
  h.clock.advance(3_600_001);
  assert.notEqual((await signup(4)).status, 429);
  for (const account of h.accounts) h.edge.records.set(account.tenantId, [{ hostname: 'app.example.com', status: 'pending' }]);
  const verify = (account) => account.client.request('/api/hostnames/app.example.com/verify', { method: 'POST' });
  for (let i = 0; i < 6; i++) assert.equal((await verify(h.accounts[0])).status, 200);
  const count = h.edge.calls.length;
  expectRateLimit(await verify(h.accounts[0]));
  assert.equal(h.edge.calls.length, count);
  assert.equal((await verify(h.accounts[1])).status, 200);
  h.clock.advance(60_001);
  assert.equal((await verify(h.accounts[0])).status, 200);
});
