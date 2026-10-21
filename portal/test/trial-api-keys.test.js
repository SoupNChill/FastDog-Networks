import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fixture, listen, request, tids, temporary } from './helpers.js';
import { createApp } from '../src/app.js';

const DAY = 86400000;
const host = 'app.example.test';
const bearer = (key) => ({ authorization: `Bearer ${key}`, 'content-type': 'application/json' });
const api = (port, key, path, method = 'GET', body) => request(port, path, { method, headers: bearer(key), body });

// A seeded tenant switched to a trial that started now (7 days, as in trials.js).
async function setup(t, config = { trialApiKey: true }, { index = 0, verified = true } = {}) {
  const f = await fixture(t, config);
  const a = await f.seed(index, verified);
  const accounts = f.store.read('accounts');
  Object.assign(accounts.tenants.find((x) => x.id === tids[index]), { plan: 'trial', hostname_limit: 1, source: 'open', created_at: new Date(f.now()).toISOString() });
  f.store.write('accounts', accounts);
  const create = (body) => a.client.call('/api/keys', 'POST', { password: a.password, scopes: ['hostnames:create', 'status:read'], ...body });
  return { f, a, create, ends: new Date(f.now() + 7 * DAY).toISOString() };
}

test('flag off: trials still get plan_required and GET /api/keys is unchanged', async (t) => {
  const { a, create } = await setup(t, {});
  assert.equal((await create({ hostnames: [host] })).data.error, 'plan_required');
  assert.deepEqual((await a.client.call('/api/keys')).data, { available: false, scopes: ['hostnames:create', 'status:read', 'connect'],
    default_days: 30, max_days: 90, keys: [], recent_use: [] });
  assert.throws(() => createApp({ dataDir: temporary(t), edge: {}, config: { origin: 'https://portal.example.test', trialApiKey: 'yes' } }), /trial API key/);
});

test('flag on: an active verified trial gets one key for one hostname that expires at the trial end', async (t) => {
  const { f, a, create, ends } = await setup(t);
  const list = await a.client.call('/api/keys');
  assert.equal(list.data.available, true);
  assert.deepEqual(list.data.trial, { max_keys: 1, max_hostnames: 1, expires_at: ends });
  const made = await create({ hostnames: [host] });
  assert.equal(made.status, 201);
  assert.deepEqual(made.data.hostnames, [host]);
  assert.equal(made.data.expires_at, ends, 'clamped from the 90-day default to the trial end');
  assert.equal(f.store.read('api_keys')[0].trial, true);
  f.advance(DAY);
  await a.client.call('/api/keys/' + made.data.id, 'DELETE');
  const short = await create({ hostnames: [host], expires_in_days: 2 });
  assert.equal(Date.parse(short.data.expires_at), f.now() + 2 * DAY, 'a shorter lifetime is kept');
  await a.client.call('/api/keys/' + short.data.id, 'DELETE');
  assert.equal((await create({ hostnames: [host], expires_in_days: 30 })).data.expires_at, ends, 'never past the trial end');
  assert.equal((await create({ hostnames: [host], password: 'wrong-password-123' })).data.error, 'password_required');
});

test('flag on: unverified users and ended or paused trials are refused', async (t) => {
  const u = await setup(t, { trialApiKey: true }, { verified: false });
  assert.equal((await u.create({ hostnames: [host] })).status, 401);
  assert.equal((await u.a.client.call('/api/keys')).data.available, false);

  const { f, a, create } = await setup(t);
  f.store.write('trials', { tenants: { [tids[0]]: { paused_at: new Date(f.now()).toISOString() } } });
  assert.equal((await create({ hostnames: [host] })).data.error, 'plan_required', 'paused');
  f.store.write('trials', { tenants: {} });
  f.advance(7 * DAY);
  assert.equal((await create({ hostnames: [host] })).data.error, 'plan_required', 'ended');
  const list = await a.client.call('/api/keys');
  assert.equal(list.data.available, false);
  assert.equal(Object.hasOwn(list.data, 'trial'), false);
  // An admin extension reopens the trial; the key ends with the extended trial.
  f.store.write('trial_overrides', { tenants: { [tids[0]]: { extra_days: 3 } } });
  const made = await create({ hostnames: [host] });
  assert.equal(made.status, 201);
  assert.equal(Date.parse(made.data.expires_at), f.now() + 3 * DAY);
  f.store.write('trials', '[]');
  assert.equal((await create({ hostnames: [host] })).data.error, 'plan_required', 'unreadable trial state fails closed');
});

test('flag on: a trial key needs exactly one hostname and only one can be live', async (t) => {
  const { a, create } = await setup(t);
  for (const hostnames of [undefined, null, [], [host, 'two.example.test'], ['*.example.test']]) {
    assert.equal((await create({ hostnames })).data.error, 'invalid_key', JSON.stringify(hostnames));
  }
  const first = await create({ hostnames: [host] });
  assert.equal(first.status, 201);
  assert.equal((await create({ hostnames: ['two.example.test'] })).data.error, 'key_limit_reached');
  await a.client.call(`/api/keys/${first.data.id}`, 'DELETE');
  assert.equal((await create({ hostnames: ['two.example.test'] })).status, 201, 'a revoked key frees the slot');
});

test('/api/v1: a trial key works for its hostname only', async (t) => {
  const { f, create } = await setup(t);
  const key = (await create({ hostnames: [host] })).data.key;
  const made = await api(f.port, key, '/api/v1/hostnames', 'POST', { hostname: host });
  assert.equal(made.status, 201);
  assert.deepEqual(f.calls.at(-1), ['create', tids[0], host, 1], 'trial hostname limit applies');
  assert.equal((await api(f.port, key, `/api/v1/hostnames/${host}`)).status, 200);
  assert.equal((await api(f.port, key, '/api/v1/hostnames', 'POST', { hostname: 'other.example.test' })).status, 403);
  assert.equal((await api(f.port, key, '/api/v1/hostnames/other.example.test')).status, 403);
});

test('/api/v1: a trial key is refused after the trial ends, while paused, or once the flag is off', async (t) => {
  const { f, create } = await setup(t);
  const key = (await create({ hostnames: [host] })).data.key;
  await api(f.port, key, '/api/v1/hostnames', 'POST', { hostname: host });
  const read = (port = f.port) => api(port, key, `/api/v1/hostnames/${host}`);
  assert.equal((await read()).status, 200);
  f.store.write('trials', { tenants: { [tids[0]]: { pause_requested_at: new Date(f.now()).toISOString() } } });
  assert.equal((await read()).status, 401, 'pausing');
  f.store.write('trials', { tenants: {} });
  // Same state, flag off.
  const off = await listen(t, createApp({ dataDir: f.dataDir, edge: f.edge, now: f.now, mailer: { async send() {} }, config: { origin: 'https://portal.example.test' } }));
  assert.equal((await read(off)).status, 401, 'flag off');
  assert.equal((await read()).status, 200);
  // A record edited to hold a second hostname is refused too.
  const records = f.store.read('api_keys');
  records[0].hostnames = [host, 'other.example.test'];
  f.store.write('api_keys', records);
  assert.equal((await read()).status, 401, 'more than one hostname');
  records[0].hostnames = [host];
  f.store.write('api_keys', records);
  f.advance(7 * DAY - 1);
  assert.equal((await read()).status, 200);
  f.advance(1);
  assert.equal((await read()).status, 401, 'trial ended');
  // An extension does not stretch an existing key past its own expiry.
  f.store.write('trial_overrides', { tenants: { [tids[0]]: { extra_days: 3 } } });
  assert.equal((await read()).status, 401);
});

test('a trial key keeps working under paid rules after an upgrade; a plain key of a trial tenant does not', async (t) => {
  const { f, create } = await setup(t);
  const key = (await create({ hostnames: [host] })).data.key;
  await api(f.port, key, '/api/v1/hostnames', 'POST', { hostname: host });
  const accounts = f.store.read('accounts');
  accounts.tenants[0].plan = 'pro';
  f.store.write('accounts', accounts);
  assert.equal((await api(f.port, key, `/api/v1/hostnames/${host}`)).status, 200, 'paid');
  const records = f.store.read('api_keys');
  delete records[0].trial;
  f.store.write('api_keys', records);
  accounts.tenants[0].plan = 'trial';
  f.store.write('accounts', accounts);
  assert.equal((await api(f.port, key, `/api/v1/hostnames/${host}`)).status, 401, 'not marked as a trial key');
});

test('flag on: paid plans are unchanged', async (t) => {
  const f = await fixture(t, { trialApiKey: true });
  const a = await f.seed();
  const list = await a.client.call('/api/keys');
  assert.equal(list.data.available, true);
  assert.equal(Object.hasOwn(list.data, 'trial'), false);
  const made = await a.client.call('/api/keys', 'POST', { password: a.password, scopes: ['status:read'] });
  assert.equal(made.status, 201);
  assert.equal(made.data.hostnames, null);
  assert.equal(Date.parse(made.data.expires_at) - f.now(), 30 * DAY);
  assert.equal(Object.hasOwn(made.data, 'trial'), false);
  assert.equal(Object.hasOwn(f.store.read('api_keys')[0], 'trial'), false);
  assert.equal((await a.client.call('/api/keys', 'POST', { password: a.password, scopes: ['status:read'] })).status, 201, 'more than one key');
});

// Polls between event-loop turns (the server runs in this process) until check() holds.
async function until(check) {
  for (let i = 0; i < 2000 && !check(); i++) await new Promise((resolve) => setTimeout(resolve, 1));
  assert.ok(check(), 'condition reached');
}
const pauseTrial = (f) => f.store.write('trials', { tenants: { [tids[0]]: { pause_requested_at: new Date(f.now()).toISOString() } } });

test('/api/v1: trial-key invariants still apply after an upgrade (flag off, extra hostname, old trial end)', async (t) => {
  const { f, create, ends } = await setup(t);
  const key = (await create({ hostnames: [host] })).data.key;
  await api(f.port, key, '/api/v1/hostnames', 'POST', { hostname: host });
  const accounts = f.store.read('accounts');
  accounts.tenants[0].plan = 'pro';
  f.store.write('accounts', accounts);
  const read = (port = f.port) => api(port, key, `/api/v1/hostnames/${host}`);
  assert.equal((await read()).status, 200, 'paid, flag on');
  const off = await listen(t, createApp({ dataDir: f.dataDir, edge: f.edge, now: f.now, mailer: { async send() {} }, config: { origin: 'https://portal.example.test' } }));
  assert.equal((await read(off)).status, 401, 'paid, flag off');
  const records = f.store.read('api_keys');
  records[0].hostnames = [host, 'other.example.test'];
  f.store.write('api_keys', records);
  assert.equal((await read()).status, 401, 'paid, two hostnames');
  records[0].hostnames = [host];
  f.store.write('api_keys', records);
  assert.equal((await read()).status, 200);
  f.advance(Date.parse(ends) - f.now());
  assert.equal((await read()).status, 401, 'paid, at the old trial end');
});

test('/api/v1: eligibility is re-checked after a delayed request body', async (t) => {
  const { f, create } = await setup(t);
  const key = (await create({ hostnames: [host] })).data.key;
  const slow = (between) => new Promise((resolve, reject) => {
    const body = JSON.stringify({ hostname: host });
    const req = http.request({ host: '127.0.0.1', port: f.port, path: '/api/v1/hostnames', method: 'POST', agent: false,
      headers: { ...bearer(key), 'content-length': Buffer.byteLength(body) } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject);
    req.write(body.slice(0, 5));
    setTimeout(() => { between(); req.end(body.slice(5)); }, 50);
  });
  assert.equal(await slow(() => pauseTrial(f)), 401, 'trial paused while the body was in flight');
  assert.equal(f.calls.some(([op]) => op === 'create'), false, 'the edge was never called');
  f.store.write('trials', { tenants: {} });
  assert.equal(await slow(() => {}), 201, 'control: nothing changed in flight');
});

test('key creation re-checks trial and suspension after the password check', async (t) => {
  const { f, create } = await setup(t);
  // The per-user password budget is written just before the password await.
  const during = async (change) => {
    const before = JSON.stringify(f.store.read('rate_limits', {}));
    const pending = create({ hostnames: [host] });
    await until(() => JSON.stringify(f.store.read('rate_limits', {})) !== before);
    change();
    return pending;
  };
  assert.equal((await during(() => pauseTrial(f))).data.error, 'plan_required', 'trial paused during the password check');
  f.store.write('trials', { tenants: {} });
  const at = f.now();
  const suspend = () => f.store.write('suspensions', { tenants: { [tids[0]]: { at: new Date(at).toISOString(), reason: 'x', revoked_before: at } } });
  assert.equal((await during(suspend)).status, 401, 'suspended during the password check');
  f.advance(1000);
  f.store.write('suspensions', { tenants: { [tids[0]]: { at: new Date(at).toISOString(), reason: 'x', revoked_before: at, resumed_at: new Date(f.now()).toISOString() } } });
  assert.deepEqual(f.store.read('api_keys', []), [], 'no key was minted to survive the resume');
});

test('flag on: a set-plan override upgrade keeps the trial key and allows paid keys; flag off is unchanged', async (t) => {
  const { f, a, create } = await setup(t);
  const made = (await create({ hostnames: [host] })).data;
  await api(f.port, made.key, '/api/v1/hostnames', 'POST', { hostname: host });
  f.store.write('trial_overrides', { tenants: { [tids[0]]: { plan: 'pro' } } });
  assert.equal((await api(f.port, made.key, `/api/v1/hostnames/${host}`)).status, 200, 'trial key survives the override upgrade');
  const list = await a.client.call('/api/keys');
  assert.equal(list.data.available, true);
  assert.equal(Object.hasOwn(list.data, 'trial'), false);
  await a.client.call(`/api/keys/${made.id}`, 'DELETE');
  const paid = await create({});
  assert.equal(paid.status, 201);
  assert.equal(paid.data.hostnames, null);
  assert.equal(Object.hasOwn(paid.data, 'trial'), false);
  assert.equal((await api(f.port, paid.data.key, `/api/v1/hostnames/${host}`)).status, 200);

  const o = await setup(t, {});
  o.f.store.write('trial_overrides', { tenants: { [tids[0]]: { plan: 'pro' } } });
  assert.equal((await o.create({})).data.error, 'plan_required', 'flag off reads the raw plan, as before');
});
