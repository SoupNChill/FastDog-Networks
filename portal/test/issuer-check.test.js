// Portal issuer-check listener (agent bootstrap): loopback-only ingress, one route, per-environment service credential,
// bounded rate limits, and the service credential authenticates nothing on any other portal route.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { randomBytes } from 'node:crypto';
import { fixture, request, listen } from './helpers.js';
import { createIssuerCheckServer, issuerCheckKeys, issuerMac, requestEncoding, replyEncoding, macMatches, MAC_HEADER, ISSUER_CHECK_PATH } from '../src/issuer-check.js';

const secret = () => randomBytes(32).toString('hex');
const body = (overrides = {}) => ({ issuer_kind: 'session', issuer_id: 'issuer-1', authorization_generation: 1, nonce: randomBytes(32).toString('base64url'), ...overrides });
const signed = (key, value) => ({ 'content-type': 'application/json', [MAC_HEADER]: issuerMac(issuerCheckKeys(key).request, requestEncoding(value)) });

async function listener(t, options = {}) {
  const key = options.secret ?? secret();
  const server = createIssuerCheckServer({ secret: key, validate: () => true, ...options });
  const port = await listen(t, server);
  const ask = (value = body(), { headers, path = ISSUER_CHECK_PATH, method = 'POST', as = key } = {}) =>
    request(port, path, { method, headers: headers ?? signed(as, value), body: value });
  return { key, server, port, ask };
}

// Drives the request handler directly to present a non-loopback peer address.
function asPeer(server, remoteAddress, value, headers) {
  const req = new PassThrough(); Object.assign(req, { method: 'POST', url: ISSUER_CHECK_PATH, headers, socket: { remoteAddress } });
  const res = new EventEmitter(); res.headersSent = false;
  return new Promise((resolve) => {
    res.writeHead = (status) => { res.statusCode = status; res.headersSent = true; };
    res.end = () => { res.emit('finish'); resolve(res.statusCode); };
    server.listeners('request')[0](req, res);
    req.end(JSON.stringify(value));
  });
}

test('an authenticated request gets only the echoed fields, valid and checked_at, MACed with the reply-direction key', async (t) => {
  const l = await listener(t, { now: () => 1700000000000 });
  const value = body({ authorization_generation: 'g-7' });
  const reply = await l.ask(value);
  assert.equal(reply.status, 200);
  assert.equal(reply.headers['cache-control'], 'no-store');
  assert.deepEqual(reply.data, { ...value, valid: true, checked_at: 1700000000000 });
  const keys = issuerCheckKeys(l.key);
  assert.ok(macMatches(issuerMac(keys.reply, replyEncoding(reply.data)), reply.headers[MAC_HEADER]));
  assert.ok(!macMatches(issuerMac(keys.request, replyEncoding(reply.data)), reply.headers[MAC_HEADER]));
  // Unknown issuer kinds are simply not valid; malformed requests are 400 before authentication.
  assert.equal((await l.ask(body({ issuer_kind: 'operator' }))).data.valid, false);
  for (const bad of [body({ nonce: 'short' }), body({ extra: 1 }), body({ authorization_generation: -1 }), body({ issuer_id: 'a/b' })]) {
    assert.equal((await l.ask(bad)).status, 400);
  }
  const { nonce, ...missing } = body();
  assert.ok(nonce);
  assert.equal((await l.ask(missing, { headers: { 'content-type': 'application/json' } })).status, 400);
});

test('validator failures are 503 and never valid', async (t) => {
  const l = await listener(t, { validate: () => { throw new Error('store unreadable'); } });
  const reply = await l.ask();
  assert.equal(reply.status, 503); assert.equal(reply.headers[MAC_HEADER], undefined);
});

test('wrong-environment keys, missing or replayed MACs are 401; other paths and methods do not exist', async (t) => {
  const l = await listener(t);
  assert.equal((await l.ask(body(), { as: secret() })).status, 401, 'other environment');
  assert.equal((await l.ask(body(), { headers: { 'content-type': 'application/json' } })).status, 401);
  const value = body();
  assert.equal((await l.ask({ ...value, issuer_id: 'issuer-2' }, { headers: signed(l.key, value) })).status, 401, 'MAC bound to every field');
  // The reply-direction key never authenticates a request.
  assert.equal((await l.ask(value, { headers: { [MAC_HEADER]: issuerMac(issuerCheckKeys(l.key).reply, requestEncoding(value)) } })).status, 401);
  assert.equal((await l.ask(body(), { path: `${ISSUER_CHECK_PATH}?x=1` })).status, 404);
  assert.equal((await l.ask(body(), { path: '/api/me' })).status, 404);
  assert.equal((await request(l.port, ISSUER_CHECK_PATH)).status, 405);
  assert.throws(() => createIssuerCheckServer({ secret: 'short', validate: () => true }), /32 characters/);
});

test('only direct loopback peers are served: non-loopback and forwarded requests are 404', async (t) => {
  const l = await listener(t);
  const value = body();
  for (const address of ['192.0.2.10', '::ffff:192.0.2.10', '10.0.0.1']) assert.equal(await asPeer(l.server, address, value, signed(l.key, value)), 404, address);
  assert.equal(await asPeer(l.server, '127.0.0.1', value, signed(l.key, value)), 200);
  for (const header of ['x-forwarded-for', 'forwarded', 'x-real-ip', 'via']) {
    assert.equal((await l.ask(body(), { headers: { ...signed(l.key, value), [header]: '192.0.2.10' } })).status, 404, header);
  }
});

test('rate limits: 60 per minute per service key and 300 per minute globally, with bounded counters', async (t) => {
  let time = 0;
  const l = await listener(t, { now: () => time });
  for (let i = 0; i < 60; i++) assert.equal((await l.ask()).status, 200);
  const limited = await l.ask();
  assert.equal(limited.status, 429); assert.equal(limited.headers['retry-after'], '60');
  // Unauthenticated requests are refused before the limiter and never consume it.
  assert.equal((await l.ask(body(), { as: secret() })).status, 401);
  time += 60000;
  assert.equal((await l.ask()).status, 200);
  // The global bucket (seam: one environment has one key, so a smaller global limit makes it observable).
  const g = await listener(t, { now: () => time, limits: { perKey: 60, global: 3 } });
  for (let i = 0; i < 3; i++) assert.equal((await g.ask()).status, 200);
  assert.equal((await g.ask()).status, 429);
});

test('the service credential is unauthenticated on every other portal route, including internal-looking paths', async (t) => {
  const key = secret();
  const f = await fixture(t, { edgeUrl: 'https://edge.example-edge.test', agentBootstrap: true });
  const a = await f.seed();
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const value = body();
  const service = { ...signed(key, value), authorization: `Bearer ${key}`, 'x-fastdog-portal-key': key, 'x-fd-csrf': key };
  const routes = [['GET', '/'], ['GET', '/hostname'], ['GET', '/agent'], ['GET', '/keys'], ['GET', '/api/me'], ['GET', '/api/hostnames'], ['POST', '/api/hostnames'],
    ['GET', '/api/hostnames/app.example.test'], ['DELETE', '/api/hostnames/app.example.test'], ['POST', '/api/hostnames/app.example.test/rotate'],
    ['GET', '/api/hostnames/app.example.test/bootstraps'], ['POST', '/api/hostnames/app.example.test/bootstraps'], ['DELETE', '/api/hostnames/app.example.test/bootstraps'],
    ['POST', '/api/hostnames/app.example.test/revoke-agent'], ['POST', '/api/hostnames/app.example.test/bootstraps/candidates/x/confirm'],
    ['POST', '/api/hostnames/app.example.test/connect-token'], ['DELETE', '/api/hostnames/app.example.test/connect-token'], ['GET', '/api/keys'], ['POST', '/api/keys'],
    ['GET', '/api/v1/hostnames/app.example.test'], ['POST', '/api/v1/hostnames/app.example.test/bootstraps'], ['POST', '/api/v1/hostnames/app.example.test/connect'],
    ['GET', '/api/connect/v1/hostname'], ['POST', '/api/connect/v1/bootstrap'], ['POST', '/api/connect/v1/command'],
    ['POST', ISSUER_CHECK_PATH], ['GET', ISSUER_CHECK_PATH], ['POST', '/internal/v1/tenants/t_aaaaaaaaaaaaaaaaaaaa/hostnames']];
  for (const [method, path] of routes) {
    const withKey = await request(f.port, path, { method, headers: { ...service, origin: 'https://portal.example.test', 'content-type': 'application/json' }, body: method === 'GET' ? undefined : value });
    const without = await request(f.port, path, { method, headers: { origin: 'https://portal.example.test', 'content-type': 'application/json' }, body: method === 'GET' ? undefined : value });
    assert.equal(withKey.status, without.status, `${method} ${path}`);
    assert.ok(withKey.status >= 300 || path === '/api/me', `${method} ${path} must not succeed (${withKey.status})`);
    if (path === '/api/me') assert.equal(withKey.data.email, null);
  }
  // The listener itself is never part of the public portal server.
  assert.equal(f.app.listeners('request').length, 1);
});
