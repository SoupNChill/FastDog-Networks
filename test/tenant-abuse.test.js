import { laneSkip } from './helpers/lanes.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { internalFile, internalHarness, hostPath, fakeSecret } from './helpers/internal.js';
import { tenants, attachTarget, edgePublicIp } from './helpers/fixtures.js';
import { expectError, expectRateLimit, jsonRequest } from './helpers/http.js';

const skip = laneSkip(existsSync(internalFile), 'lane A not merged: internal server absent');

test('verify allows six calls per minute per tenant and recovers with the clock', { skip }, async (t) => {
  const h = await internalHarness(t);
  for (const tid of tenants) assert.equal((await h.create(tid, 'app.example.com')).status, 201);
  for (let i = 0; i < 6; i++) {
    const start = h.resolver.calls.length;
    const response = await h.request(hostPath(tenants[0], 'app.example.com', '/verify'), { method: 'POST' });
    assert.equal(response.status, 200);
    assert.equal(response.body.verified, false);
    const calls = h.resolver.calls.slice(start);
    for (const type of ['CNAME', 'A', 'TXT']) assert.ok(calls.filter((call) => call.type === type).length <= 1);
  }
  const calls = h.resolver.calls.length;
  expectRateLimit(await h.request(hostPath(tenants[0], 'app.example.com', '/verify'), { method: 'POST' }));
  assert.equal(h.resolver.calls.length, calls, 'rate-limited calls must not resolve DNS');
  assert.equal((await h.request(hostPath(tenants[1], 'app.example.com', '/verify'), { method: 'POST' })).status, 200);
  h.clock.advance(60_001);
  assert.equal((await h.request(hostPath(tenants[0], 'app.example.com', '/verify'), { method: 'POST' })).status, 200);
});

test('internal factory rejects missing, short, and operator-equivalent portal keys', { skip }, async (t) => {
  const { createInternalServer } = await import(internalFile.href);
  const h = await internalHarness(t);
  for (const portalKey of [undefined, '', 'fake-short', h.agentToken]) {
    assert.throws(() => createInternalServer({ ...h, portalKey }));
  }
  assert.equal((await jsonRequest(h.server, '/health')).status, 200);
  assert.deepEqual((await jsonRequest(h.server, '/health')).body, { ok: true });
  expectError(await h.request('/internal/v1/no-such-route'), 404, 'not_found');
  expectError(await h.request(hostPath(tenants[0]), { method: 'PATCH' }), 405, 'method_not_allowed');
});

test('credential rotation allows five per hostname per day and recovers', { skip }, async (t) => {
  const h = await internalHarness(t);
  const active = await h.activate(tenants[0], 'app.example.com');
  await h.activate(tenants[0], 'second.example.com');
  const tokens = new Set([active.credential.token]);
  const path = hostPath(tenants[0], active.hostname, '/credentials/rotate');
  for (let i = 0; i < 5; i++) {
    const result = await h.request(path, { method: 'POST' });
    assert.equal(result.status, 200);
    assert.ok(!tokens.has(result.body.credential.token));
    tokens.add(result.body.credential.token);
  }
  expectRateLimit(await h.request(path, { method: 'POST' }));
  assert.equal(h.closed.filter((host) => host === active.hostname).length, 5);
  assert.equal((await h.request(hostPath(tenants[0], 'second.example.com', '/credentials/rotate'), { method: 'POST' })).status, 200);
  h.clock.advance(86_400_001);
  assert.equal((await h.request(path, { method: 'POST' })).status, 200);
});

test('limits count active plus pending, and pending expires exactly at 24 hours', { skip }, async (t) => {
  const h = await internalHarness(t);
  await h.activate(tenants[0], 'active.example.com');
  const pending = await h.create(tenants[0], 'pending.example.com', 2);
  assert.equal(pending.status, 201);
  assert.equal(Date.parse(pending.body.expires_at) - Date.parse(pending.body.created_at), 86_400_000);
  expectError(await h.create(tenants[0], 'third.example.com', 2), 409, 'hostname_limit_reached');
  assert.equal((await h.create(tenants[1], 'third.example.com', 2)).status, 201);
  h.clock.advance(86_399_999);
  assert.equal((await h.request(hostPath(tenants[0], 'pending.example.com'))).status, 200);
  h.clock.advance(1);
  for (const [method, suffix] of [['GET', ''], ['POST', '/verify'], ['POST', '/credentials/rotate'], ['GET', '/agent'], ['DELETE', '']]) {
    expectError(await h.request(hostPath(tenants[0], 'pending.example.com', suffix), { method }), 404, 'hostname_not_found');
  }
  const listed = await h.request(hostPath(tenants[0]));
  assert.deepEqual(listed.body.hostnames.map((item) => item.hostname), ['active.example.com']);
  assert.equal((await h.create(tenants[0], 'third.example.com', 2)).status, 201);
  const renewed = await h.create(tenants[1], 'pending.example.com', 2);
  assert.equal(renewed.status, 201);
  assert.notEqual(renewed.body.dns.txt.value, pending.body.dns.txt.value);
});

test('request validation: 16 KB cap, invalid JSON and invalid limits', { skip }, async (t) => {
  const h = await internalHarness(t);
  const path = hostPath(tenants[0]);
  expectError(await h.request(path, { method: 'POST', raw: '{' }), 400, 'invalid_json');
  expectError(await h.request(path, { method: 'POST', body: { hostname: 'app.example.com', padding: 'a'.repeat(16 * 1024) } }), 413, 'payload_too_large');
  for (const limit of [0, -1, 1001, 1.5, '3', null]) expectError(await h.create(tenants[0], 'app.example.com', limit), 400, 'invalid_limit');
});

test('reserved suffixes reject case and subdomain forms but not string suffix collisions', { skip }, async (t) => {
  const h = await internalHarness(t);
  for (const host of ['reserved.example.com', 'RESERVED.EXAMPLE.COM.', 'x.reserved.example.com',
    'X.Y.Reserved.Example.Com.', attachTarget, attachTarget.toUpperCase()]) {
    expectError(await h.create(tenants[0], host), 400, 'reserved_hostname');
  }
  for (const host of ['notreserved.example.com', 'reserved.example.com.example.test']) {
    assert.equal((await h.create(tenants[0], host)).status, 201);
  }
  assert.equal(h.resolver.calls.length, 0);
});

test('DNS timeouts return dns_timeout; a resolver that never settles cannot hang verification', { skip, timeout: 15_000 }, async (t) => {
  const h = await internalHarness(t);
  const host = 'timeout.example.com';
  assert.equal((await h.create(tenants[0], host)).status, 201);
  const timeout = Object.assign(new Error('fake resolver timeout'), { code: 'ETIMEOUT' });
  for (const type of ['CNAME', 'A', 'TXT']) h.resolver.set(type, type === 'TXT' ? `_fastdog-challenge.${host}` : host, timeout);
  const check = async () => {
    const response = await h.request(hostPath(tenants[0], host, '/verify'), { method: 'POST', timeout: 6500 });
    assert.equal(response.status, 200);
    assert.equal(response.body.verified, false);
    assert.equal(response.body.checks.routing.error, 'dns_timeout');
    assert.equal(response.body.checks.ownership.error, 'dns_timeout');
  };
  await check();
  for (const type of ['CNAME', 'A', 'TXT']) h.resolver.set(type, type === 'TXT' ? `_fastdog-challenge.${host}` : host, () => new Promise(() => {}));
  await check();
});

test('routing and exact TXT ownership are both required; split TXT strings are joined', { skip }, async (t) => {
  const h = await internalHarness(t);
  const host = 'proof.example.com';
  const claim = await h.create(tenants[0], host);
  assert.equal(claim.status, 201);
  const txt = claim.body.dns.txt.value;
  const verify = () => h.request(hostPath(tenants[0], host, '/verify'), { method: 'POST' });
  h.resolver.set('TXT', `_fastdog-challenge.${host}`, [[txt]]);
  assert.equal((await verify()).body.verified, false);
  h.resolver.set('CNAME', host, [attachTarget]);
  for (const value of [`prefix-${txt}`, `${txt}-suffix`]) {
    h.resolver.set('TXT', `_fastdog-challenge.${host}`, [[value]]);
    const response = await verify();
    assert.equal(response.body.verified, false);
    assert.equal(response.body.checks.ownership.error, 'txt_mismatch');
  }
  h.resolver.set('TXT', `_fastdog-challenge.${host}`, [[txt.slice(0, 15), txt.slice(15)]]);
  assert.equal((await verify()).body.verified, true);
});

test('A routing proof works without CNAME and cyclic CNAME lookup stays bounded', { skip }, async (t) => {
  const h = await internalHarness(t);
  const claim = await h.create(tenants[0], 'a.example.com');
  h.resolver.set('A', claim.body.hostname, [edgePublicIp]);
  h.resolver.set('TXT', claim.body.dns.txt.name, [[claim.body.dns.txt.value]]);
  assert.equal((await h.request(hostPath(tenants[0], claim.body.hostname, '/verify'), { method: 'POST' })).body.verified, true);
  const loop = await h.create(tenants[0], 'loop.example.com');
  h.resolver.set('CNAME', loop.body.hostname, ['loop.example.com']);
  const start = h.resolver.calls.length;
  const response = await h.request(hostPath(tenants[0], loop.body.hostname, '/verify'), { method: 'POST' });
  assert.equal(response.status, 200);
  assert.equal(response.body.verified, false);
  assert.ok(h.resolver.calls.slice(start).filter((call) => call.type === 'CNAME').length <= 6);
});

test('tls ask exposes no data and accepts only active claims', { skip }, async (t) => {
  const h = await internalHarness(t);
  const ask = (host) => jsonRequest(h.server, `/tls/ask?domain=${encodeURIComponent(host)}`);
  const claim = await h.create(tenants[0], 'app.example.com');
  for (const host of ['app.example.com', 'unknown.example.com', '*.example.com']) {
    const response = await ask(host);
    assert.equal(response.status, 404);
    assert.equal(response.text, '');
  }
  h.prove(claim.body);
  assert.equal((await h.request(hostPath(tenants[0], 'app.example.com', '/verify'), { method: 'POST' })).body.verified, true);
  assert.equal((await ask('APP.EXAMPLE.COM.')).status, 404, 'non-canonical spelling is not approved');
  const active = await ask('app.example.com');
  assert.equal(active.status, 200);
  assert.equal(active.text, '');
  assert.equal((await h.request(hostPath(tenants[0], 'app.example.com'), { method: 'DELETE' })).status, 200);
  assert.equal((await ask('app.example.com')).status, 404);
});

test('verify after pending expiry with valid DNS is hostname_not_found; the stale proof cannot activate a new claim', { skip }, async (t) => {
  const h = await internalHarness(t);
  const host = 'late.example.com';
  const first = await h.create(tenants[0], host);
  h.prove(first.body);
  h.clock.advance(86_400_000);
  const calls = h.resolver.calls.length;
  expectError(await h.request(hostPath(tenants[0], host, '/verify'), { method: 'POST' }), 404, 'hostname_not_found');
  assert.equal(h.resolver.calls.length, calls, 'expired claims are not re-checked in DNS');
  assert.deepEqual((await h.request(hostPath(tenants[0]))).body, { hostnames: [] });
  assert.equal((await jsonRequest(h.server, `/tls/ask?domain=${host}`)).status, 404);
  const renewed = await h.create(tenants[0], host);
  assert.equal(renewed.status, 201);
  assert.notEqual(renewed.body.dns.txt.value, first.body.dns.txt.value);
  const stale = await h.request(hostPath(tenants[0], host, '/verify'), { method: 'POST' });
  assert.equal(stale.status, 200);
  assert.deepEqual([stale.body.verified, stale.body.status, stale.body.credential], [false, 'pending', undefined]);
  h.prove(renewed.body);
  const active = await h.request(hostPath(tenants[0], host, '/verify'), { method: 'POST' });
  assert.deepEqual([active.body.verified, active.body.status], [true, 'active']);
});

test('logs for 401/409/429/500 and POST bodies keep only method, route template, status and duration', { skip }, async (t) => {
  let failAgentLookup = false;
  const h = await internalHarness(t, { registry: {
    getAgentByHost: () => { if (failAgentLookup) throw new Error('synthetic registry failure'); return null; },
    closeHost: () => {},
  } });
  const marker = fakeSecret();
  const active = await h.activate(tenants[0], 'owned.example.com');
  const secretHeaders = { authorization: `Bearer ${marker}`, cookie: `session=${marker}`, 'x-forwarded-for': '198.51.100.7' };
  const responses = [
    await h.request(hostPath(tenants[0]), { method: 'POST', headers: { ...secretHeaders, 'x-fastdog-portal-key': marker },
      body: { hostname: 'denied.example.com', hostname_limit: 5, password: marker } }),
    await h.request(hostPath(tenants[1]), { method: 'POST', headers: secretHeaders,
      body: { hostname: 'owned.example.com', hostname_limit: 5, token: marker } }),
    await h.request(hostPath(tenants[0], 'owned.example.com', '/credentials/rotate'), { method: 'POST', headers: secretHeaders, body: { note: marker } }),
  ];
  const pending = await h.create(tenants[0], 'pending.example.com');
  for (let i = 0; i < 7; i++) responses.push(await h.request(hostPath(tenants[0], 'pending.example.com', '/verify'), { method: 'POST', body: { secret: marker } }));
  failAgentLookup = true;
  responses.push(await h.request(`${hostPath(tenants[0], 'owned.example.com')}?token=${marker}`, { headers: secretHeaders }));
  const statuses = new Set(responses.map((response) => response.status));
  for (const status of [401, 409, 429, 500]) assert.ok(statuses.has(status), `exercised ${status}`);
  assert.deepEqual(responses.at(-1).body, { error: 'internal_error' });
  const events = h.logs.map((args) => { assert.equal(args.length, 1); return args[0]; });
  for (const status of [401, 409, 429, 500]) assert.ok(events.some((event) => event.status === status), `logged ${status}`);
  for (const event of events) {
    if (!('method' in event)) { assert.deepEqual(Object.keys(event).filter((key) => !['status', 'reason'].includes(key)), []); continue; }
    assert.deepEqual(Object.keys(event).sort(), ['duration', 'method', 'route', 'status']);
    assert.match(event.route, /^(not_found|\/health|\/tls\/ask|\/internal\/v1\/tenants\/:tid\/hostnames(\/:hostname(\/[a-z/]+)?)?)$/);
  }
  const text = JSON.stringify(h.logs);
  // No client address in any form: the internal API logs no IP at all (stricter than the /24 or /48 allowance).
  for (const value of [marker, h.portalKey, active.credential.token, pending.body.dns.txt.value, ...tenants, 'owned.example.com',
    'pending.example.com', 'denied.example.com', '127.0.0.1', '127.0.0', '::ffff', '198.51.100', 'synthetic registry failure']) {
    assert.ok(!text.includes(value), `log leaked ${value === marker ? 'marker' : value}`);
  }
});

test('pending claims cannot rotate or read agent status; logs omit identifiers and query values', { skip }, async (t) => {
  const h = await internalHarness(t);
  const claim = await h.create(tenants[0], 'private.example.com');
  const marker = fakeSecret();
  for (const [method, suffix] of [['POST', '/credentials/rotate'], ['GET', '/agent']]) {
    expectError(await h.request(hostPath(tenants[0], claim.body.hostname, suffix), { method }), 409, 'not_active');
  }
  await h.request(`${hostPath(tenants[0], claim.body.hostname)}?token=${marker}`);
  const logs = JSON.stringify(h.logs);
  for (const value of [marker, tenants[0], claim.body.hostname, claim.body.dns.txt.value, h.portalKey]) assert.ok(!logs.includes(value));
});
