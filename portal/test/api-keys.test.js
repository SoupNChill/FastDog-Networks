import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, tids, request } from './helpers.js';

const edgeUrl = 'https://edge.example-edge.test';
const DAY = 86400000;
const bearer = (key, extra = {}) => ({ authorization: `Bearer ${key}`, ...extra });
const api = (f, key, path, method = 'GET', body) => request(f.port, path, { method,
  headers: bearer(key, body === undefined ? {} : { 'content-type': 'application/json' }), body });

async function setup(t) {
  const f = await fixture(t, { edgeUrl });
  const a = await f.seed();
  pw = a.password;
  return { f, a };
}
let pw;
const create = (client, body) => client.call('/api/keys', 'POST', { password: pw, ...body });

test('keys are created by a verified session with CSRF, shown once and stored as a digest', async (t) => {
  const { f, a } = await setup(t);
  assert.equal((await request(f.port, '/api/keys', { method: 'POST', headers: { 'content-type': 'application/json' }, body: { scopes: ['status:read'] } })).status, 401);
  assert.equal((await a.client.call('/api/keys', 'POST', { scopes: ['status:read'] }, { 'x-fd-csrf': 'wrong' })).status, 401);
  const made = await create(a.client, { name: 'ci', scopes: ['status:read'] });
  assert.equal(made.status, 201);
  assert.match(made.data.key, /^fdak_[A-Za-z0-9_-]{43}$/);
  assert.equal(Date.parse(made.data.expires_at) - f.now(), 30 * DAY, 'default 30 days');
  assert.equal(JSON.stringify(f.store.read('api_keys', [])).includes(made.data.key), false);
  const list = await a.client.call('/api/keys');
  assert.equal(list.status, 200);
  assert.equal(list.data.keys.length, 1);
  assert.equal(list.data.keys[0].state, 'active');
  assert.equal(JSON.stringify(list.data).includes(made.data.key), false, 'never shown again');
  assert.deepEqual(list.data.scopes, ['hostnames:create', 'status:read', 'connect']);
  assert.equal((await create(a.client, { scopes: ['status:read'], password: 'wrong-password-123' })).status, 403, 'current password required');
  const unverified = await f.seed(1, false);
  assert.equal((await create(unverified.client, { scopes: ['status:read'] })).status, 401);
});

test('key input is validated: scopes, lifetime and hostnames', async (t) => {
  const { a } = await setup(t);
  for (const body of [{}, { scopes: [] }, { scopes: ['hostnames:delete'] }, { scopes: ['status:read', 'status:read'] },
    { scopes: ['status:read'], expires_in_days: 91 }, { scopes: ['status:read'], expires_in_days: 0 },
    { scopes: ['status:read'], expires_in_days: 1.5 }, { scopes: ['status:read'], hostnames: ['*.example.test'] },
    { scopes: ['status:read'], name: '<b>' }]) {
    assert.equal((await create(a.client, body)).status, 400, JSON.stringify(body));
  }
  const max = await create(a.client, { scopes: ['status:read'], expires_in_days: 90, hostnames: ['App.Example.Test'] });
  assert.equal(max.status, 201);
  assert.deepEqual(max.data.hostnames, ['app.example.test']);
});

test('creation is limited to 5 per hour and 10 live keys per tenant', async (t) => {
  const { f, a } = await setup(t);
  for (let i = 0; i < 5; i++) assert.equal((await create(a.client, { scopes: ['status:read'] })).status, 201);
  assert.equal((await create(a.client, { scopes: ['status:read'] })).status, 429);
  f.advance(3600001);
  for (let i = 0; i < 5; i++) assert.equal((await create(a.client, { scopes: ['status:read'] })).status, 201);
  f.advance(3600001);
  assert.equal((await create(a.client, { scopes: ['status:read'] })).status, 409);
});

test('keys need a paid plan; there is no free plan', async (t) => {
  const { f, a } = await setup(t);
  const accounts = f.store.read('accounts');
  accounts.tenants[0].plan = 'free';
  f.store.write('accounts', accounts);
  assert.equal((await create(a.client, { scopes: ['status:read'] })).status, 403);
  assert.equal((await a.client.call('/api/keys')).data.available, false);
});

test('scopes gate each route; delete is never available over the API', async (t) => {
  const { f, a } = await setup(t);
  const status = (await create(a.client, { scopes: ['status:read'] })).data.key;
  const creator = (await create(a.client, { scopes: ['hostnames:create'] })).data.key;
  const connect = (await create(a.client, { scopes: ['connect'] })).data.key;
  assert.equal((await api(f, connect, '/api/v1/hostnames/app.example.test/connect', 'POST', { origin: 'http://127.0.0.1:3000' })).status, 404);
  assert.equal((await api(f, status, '/api/v1/hostnames', 'POST', { hostname: 'app.example.test' })).status, 403);
  const made = await api(f, creator, '/api/v1/hostnames', 'POST', { hostname: 'app.example.test' });
  assert.equal(made.status, 201);
  assert.ok(made.data.dns.cname);
  assert.deepEqual(f.calls.at(-1), ['create', tids[0], 'app.example.test', 3]);
  assert.equal((await api(f, connect, '/api/v1/hostnames/app.example.test/connect', 'POST', { origin: 'http://127.0.0.1:3000' })).status, 409, 'pending hostnames cannot be connected');
  const verified = await api(f, creator, '/api/v1/hostnames/app.example.test/verify', 'POST');
  assert.equal(verified.status, 200);
  assert.equal(verified.data.credential, undefined, 'verify never hands out an agent credential');
  assert.equal((await api(f, connect, '/api/v1/hostnames/app.example.test/status')).status, 403);
  const st = await api(f, status, '/api/v1/hostnames/app.example.test/status');
  assert.equal(st.status, 200);
  assert.equal(st.data.verdict.shadow, true);
  assert.equal(JSON.stringify(st.data).includes('/internal'), false);
  assert.equal((await api(f, status, '/api/v1/hostnames/app.example.test')).status, 200);
  assert.equal((await api(f, connect, '/api/v1/hostnames/app.example.test')).status, 403);
  assert.equal((await api(f, status, '/api/v1/hostnames/app.example.test/connect', 'POST', { origin: 'http://127.0.0.1:3000' })).status, 403);
  await f.client.call('/api/me');
  const cmd = await api(f, connect, '/api/v1/hostnames/app.example.test/connect', 'POST', { origin: 'http://127.0.0.1:3000' });
  assert.equal(cmd.status, 200);
  assert.match(cmd.data.command, /--hostname 'app\.example\.test'/);
  assert.equal(Object.hasOwn(cmd.data, 'env_file'), false);
  const docker = await api(f, connect, '/api/v1/hostnames/app.example.test/connect', 'POST', { origin: 'http://127.0.0.1:3000', platform: 'docker' });
  assert.equal(docker.status, 200);
  assert.match(docker.data.env_file, /^fastdog-agent-app-example-test-[0-9a-f]{10}\.env$/);
  assert.equal(docker.data.env_file, docker.data.command.match(/--env-file (\S+)/)[1]);
  assert.deepEqual(f.calls.at(-1), ['rotate', tids[0], 'app.example.test']);
  for (const method of ['DELETE', 'PUT']) {
    assert.equal((await api(f, creator, '/api/v1/hostnames/app.example.test', method)).status, 405);
  }
  assert.equal(f.calls.some(([name]) => name === 'delete'), false);
  assert.equal((await api(f, creator, '/api/v1/keys', 'POST', { scopes: ['connect'] })).status, 404);
});

test('a key never makes a key and never rides a cookie; secrets in URLs are refused', async (t) => {
  const { f, a } = await setup(t);
  const key = (await create(a.client, { scopes: ['status:read', 'hostnames:create', 'connect'] })).data.key;
  assert.equal((await request(f.port, '/api/keys', { method: 'POST', headers: bearer(key, { 'content-type': 'application/json', origin: 'https://portal.example.test' }), body: { scopes: ['connect'] } })).status, 401);
  assert.equal((await request(f.port, `/api/v1/hostnames/app.example.test/status?key=${key}`)).status, 401);
  assert.equal((await request(f.port, '/api/v1/hostnames/app.example.test/status', { headers: { cookie: a.client.cookie } })).status, 401);
  assert.equal((await request(f.port, '/api/v1/hostnames/app.example.test/status', { headers: bearer('fdct_' + key.slice(5)) })).status, 401);
});

test('tenant isolation and hostname allow-lists', async (t) => {
  const { f, a } = await setup(t);
  const b = await f.seed(1);
  await b.client.call('/api/hostnames', 'POST', { hostname: 'other.example.test' });
  await b.client.call('/api/hostnames/other.example.test/verify', 'POST');
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  await a.client.call('/api/hostnames', 'POST', { hostname: 'two.example.test' });
  const key = (await create(a.client, { scopes: ['status:read', 'hostnames:create'], hostnames: ['app.example.test'] })).data.key;
  assert.equal((await api(f, key, '/api/v1/hostnames/app.example.test/status')).status, 200);
  assert.equal((await api(f, key, '/api/v1/hostnames/two.example.test/status')).status, 403);
  assert.equal((await api(f, key, '/api/v1/hostnames/other.example.test/status')).status, 403);
  const open = (await create(a.client, { scopes: ['status:read'] })).data.key;
  assert.equal((await api(f, open, '/api/v1/hostnames/other.example.test/status')).status, 404, "another tenant's site is not found");
  assert.equal((await api(f, key, '/api/v1/hostnames', 'POST', { hostname: 'new.example.test' })).status, 403);
  // Another tenant cannot list or revoke these keys.
  const id = (await a.client.call('/api/keys')).data.keys[0].id;
  assert.equal((await b.client.call(`/api/keys/${id}`, 'DELETE')).status, 404);
  assert.equal((await b.client.call('/api/keys')).data.keys.length, 0);
  // Removing the hostname revokes keys limited to it.
  await a.client.call('/api/hostnames/app.example.test', 'DELETE');
  assert.equal((await api(f, key, '/api/v1/hostnames/app.example.test/status')).status, 401);
});

test('revocation, expiry and password changes end keys on the next request', async (t) => {
  const { f, a } = await setup(t);
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const made = (await create(a.client, { scopes: ['status:read'], expires_in_days: 1 })).data;
  assert.equal((await api(f, made.key, '/api/v1/hostnames/app.example.test/status')).status, 200);
  f.advance(DAY + 1);
  assert.equal((await api(f, made.key, '/api/v1/hostnames/app.example.test/status')).status, 401);
  assert.equal((await a.client.call('/api/keys')).data.keys.find((k) => k.id === made.id).state, 'expired');
  const second = (await create(a.client, { scopes: ['status:read'] })).data;
  assert.equal((await a.client.call(`/api/keys/${second.id}`, 'DELETE')).data.state, 'revoked');
  assert.equal((await api(f, second.key, '/api/v1/hostnames/app.example.test/status')).status, 401);
  const third = (await create(a.client, { scopes: ['status:read'] })).data;
  const accounts = f.store.read('accounts');
  accounts.users[0].auth_version = 2;
  f.store.write('accounts', accounts);
  assert.equal((await api(f, third.key, '/api/v1/hostnames/app.example.test/status')).status, 401);
  accounts.users[0].auth_version = 1;
  accounts.tenants[0].status = 'suspended';
  f.store.write('accounts', accounts);
  assert.equal((await api(f, third.key, '/api/v1/hostnames/app.example.test/status')).status, 401);
});

test('per-key rate limits, connect budgets and an audit log without secrets', async (t) => {
  const { f, a } = await setup(t);
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const key = (await create(a.client, { scopes: ['connect', 'status:read'] })).data.key;
  for (let i = 0; i < 3; i++) assert.equal((await api(f, key, '/api/v1/hostnames/app.example.test/connect', 'POST', { origin: 'http://127.0.0.1:3000' })).status, 200);
  assert.equal((await api(f, key, '/api/v1/hostnames/app.example.test/connect', 'POST', { origin: 'http://127.0.0.1:3000' })).status, 429, '3 key rotations a day');
  let last;
  for (let i = 0; i < 60; i++) last = await api(f, key, '/api/v1/hostnames/app.example.test');
  assert.equal(last.status, 429);
  const audit = f.store.read('api_key_audit', []);
  assert.ok(audit.length >= 60);
  assert.equal(JSON.stringify(audit).includes(key), false);
  assert.ok(audit.every((e) => e.tenant_id === tids[0] && e.route.startsWith('/api/v1/hostnames')));
  const view = await a.client.call('/api/keys');
  assert.ok(view.data.keys[0].last_used_at);
  assert.ok(view.data.recent_use.length > 0);
  assert.equal(JSON.stringify(view.data).includes('app.example.test/'), false, 'routes are templates');
});
