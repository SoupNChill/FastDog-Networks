import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { join } from 'node:path';
import { start } from '../server.js';
import { emptyAccounts, createStore } from '../src/store.js';
import { createInvites } from '../src/invites.js';
import { TERMS_VERSION } from '../src/terms.js';
import { fakeSecret, browser, listen, origin, temporary, linkToken } from './helpers.js';

// Loopback stand-in for the edge internal API that enforces hostname_limit like src/internal/claims.js.
function loopbackEdge(t, portalKey) {
  const claims = new Map();
  const creates = [];
  const reply = (res, status, data) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(data)); };
  const server = http.createServer(async (req, res) => {
    const parts = [];
    for await (const part of req) parts.push(part);
    const body = parts.length ? JSON.parse(Buffer.concat(parts).toString('utf8')) : {};
    if (req.headers['x-fastdog-portal-key'] !== portalKey) return reply(res, 401, { error: 'unauthorized' });
    const m = req.url.match(/^\/internal\/v1\/tenants\/(t_[a-z2-7]{20})\/hostnames(?:\/([^/]+)(?:\/(verify))?)?$/);
    if (!m) return reply(res, 404, { error: 'not_found' });
    const [, tid, host, action] = m;
    const own = [...claims.values()].filter((c) => c.tid === tid);
    if (!host && req.method === 'GET') return reply(res, 200, { hostnames: own.map(({ tid: _, ...c }) => c) });
    if (!host && req.method === 'POST') {
      creates.push([tid, body.hostname, body.hostname_limit]);
      if (claims.has(body.hostname)) return reply(res, 409, { error: 'hostname_unavailable' });
      if (own.length >= body.hostname_limit) return reply(res, 409, { error: 'hostname_limit_reached' });
      const claim = { tid, hostname: body.hostname, status: 'pending', created_at: new Date().toISOString() };
      claims.set(body.hostname, claim);
      return reply(res, 201, { hostname: claim.hostname, status: claim.status, created_at: claim.created_at });
    }
    const claim = claims.get(decodeURIComponent(host));
    if (!claim || claim.tid !== tid) return reply(res, 404, { error: 'hostname_not_found' });
    if (action === 'verify') {
      claim.status = 'active';
      return reply(res, 200, { hostname: claim.hostname, status: 'active', verified: true });
    }
    return reply(res, 200, { hostname: claim.hostname, status: claim.status, created_at: claim.created_at });
  });
  return listen(t, server).then((port) => ({ url: `http://127.0.0.1:${port}`, creates }));
}

async function freePort() {
  const probe = createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

test('OPEN_SIGNUP flip and rollback on one data dir: invite-only, open trial, then invite-only again', async (t) => {
  const dataDir = temporary(t);
  const portalKey = fakeSecret();
  const edge = await loopbackEdge(t, portalKey);
  const logs = [];
  t.mock.method(console, 'log', (line) => { try { logs.push(JSON.parse(line)); } catch { /* not JSON */ } });
  const outbox = join(dataDir, 'outbox');
  const mail = (to) => (existsSync(outbox) ? readdirSync(outbox) : []).map((f) => JSON.parse(readFileSync(join(outbox, f), 'utf8'))).filter((m) => m.to === to);
  const accounts = () => createStore(dataDir).read('accounts', emptyAccounts());
  const reasons = () => logs.filter((e) => e.event === 'signup').map((e) => e.reason ?? e.outcome);
  const boot = async (flag) => {
    const port = await freePort();
    const app = start({ STATE_DIRECTORY: dataDir, PORTAL_ORIGIN: origin, PORTAL_KEY: portalKey, EDGE_INTERNAL_URL: edge.url,
      PORTAL_PORT: String(port), ...(flag === undefined ? {} : { OPEN_SIGNUP: flag }) });
    await once(app, 'listening');
    const client = browser(port);
    return { client, port, stop: () => new Promise((resolve) => { app.close(resolve); app.closeAllConnections(); }) };
  };
  const login = async (port, email, password) => {
    const c = browser(port);
    await c.call('/api/me');
    const result = await c.call('/api/login', 'POST', { email, password });
    await c.call('/api/me');
    return { c, status: result.status };
  };
  const signup = async (client, email, password = fakeSecret(), extra = { accept_terms: true }) => {
    const result = await client.call('/api/signup', 'POST', { email, password, ...extra });
    assert.deepEqual([result.status, result.data], [200, { ok: true }], email);
  };

  // 1. Flag unset (default): open registration gets the generic response and creates nothing.
  let portal = await boot(undefined);
  await portal.client.call('/api/me');
  assert.equal((await portal.client.call('/api/me')).data.open_signup, false);
  await signup(portal.client, 'early@example.test');
  assert.equal(accounts().users.length, 0);
  assert.deepEqual(mail('early@example.test'), []);
  assert.deepEqual(reasons(), []);
  await portal.stop();

  // 2. OPEN_SIGNUP=1: an open registration becomes an unverified trial tenant.
  portal = await boot('1');
  await portal.client.call('/api/me');
  assert.equal((await portal.client.call('/api/me')).data.open_signup, true);
  const email = 'owner@example.test', firstPassword = fakeSecret(), password = fakeSecret();
  // Without accept_terms === true the open registration is refused generically and creates nothing.
  await signup(portal.client, 'noterms@example.test', fakeSecret(), { accept_terms: 'true' });
  assert.equal(accounts().users.length, 0);
  assert.deepEqual(mail('noterms@example.test'), []);
  await signup(portal.client, email, firstPassword);
  await signup(portal.client, 'pending@example.test');
  assert.deepEqual(reasons(), ['created', 'created']);
  assert.ok(!JSON.stringify(logs).includes('example.test'), 'logs carry reason codes only');
  const owner = accounts().users.find((u) => u.email === email);
  assert.equal(owner.email_verified_at, null);
  assert.equal(owner.terms.tos_version, TERMS_VERSION);
  const tenant = accounts().tenants.find((x) => x.id === owner.tenant_id);
  assert.deepEqual({ ...tenant, id: undefined }, { id: undefined, name: '', plan: 'trial', hostname_limit: 1, status: 'active', source: 'open' });
  // Before verification: login works but no hostname, connect token or API key.
  let session = await login(portal.port, email, firstPassword);
  assert.equal(session.status, 200);
  assert.deepEqual((await session.c.call('/api/me')).data.tenant, { id: tenant.id, plan: 'trial', hostname_limit: 1 });
  assert.equal((await session.c.call('/api/me')).data.email_verified, false);
  assert.equal((await session.c.call('/api/hostnames', 'POST', { hostname: 'app.example.test' })).status, 401);
  assert.deepEqual(edge.creates, []);
  // Verify from the outbox link; open verification sets the real password.
  const [verify] = mail(email);
  assert.equal(verify.kind, 'verify-email');
  assert.equal((await portal.client.call('/api/verify-email', 'POST', { token: linkToken(verify), password })).status, 200);
  assert.equal((await login(portal.port, email, firstPassword)).status, 401);
  session = await login(portal.port, email, password);
  assert.equal(session.status, 200);
  assert.equal((await session.c.call('/api/me')).data.email_verified, true);
  // Trial limits: one hostname, no API keys, three connect tokens per hour.
  assert.equal((await session.c.call('/api/hostnames', 'POST', { hostname: 'app.example.test' })).status, 201);
  assert.equal((await session.c.call('/api/hostnames', 'POST', { hostname: 'second.example.test' })).data.error, 'hostname_limit_reached');
  assert.deepEqual(edge.creates.map(([tid, , limit]) => [tid, limit]), [[tenant.id, 1], [tenant.id, 1]]);
  assert.equal((await session.c.call('/api/hostnames/app.example.test/verify', 'POST')).status, 200);
  assert.equal((await session.c.call('/api/keys')).data.available, false);
  assert.equal((await session.c.call('/api/keys', 'POST', { scopes: ['status:read'], password })).data.error, 'plan_required');
  for (let i = 0; i < 3; i++) assert.equal((await session.c.call('/api/hostnames/app.example.test/connect-token', 'POST')).status, 201);
  assert.equal((await session.c.call('/api/hostnames/app.example.test/connect-token', 'POST')).status, 429);
  await portal.stop();

  // 3. Rollback with OPEN_SIGNUP=0: open registration is refused generically again.
  portal = await boot('0');
  await portal.client.call('/api/me');
  assert.equal((await portal.client.call('/api/me')).data.open_signup, false);
  const before = accounts().users.length;
  await signup(portal.client, 'late@example.test');
  await signup(portal.client, 'pending@example.test');
  assert.equal(accounts().users.length, before);
  assert.deepEqual(mail('late@example.test'), []);
  assert.equal(mail('pending@example.test').length, 1, 'no new link for a pending address after rollback');
  assert.deepEqual(reasons(), ['created', 'created']);
  // The account created while open keeps its login, hostname and trial limits.
  session = await login(portal.port, email, password);
  assert.equal(session.status, 200);
  assert.deepEqual((await session.c.call('/api/me')).data.tenant, { id: tenant.id, plan: 'trial', hostname_limit: 1 });
  assert.deepEqual((await session.c.call('/api/hostnames')).data.hostnames.map((h) => [h.hostname, h.status]), [['app.example.test', 'active']]);
  assert.equal((await session.c.call('/api/hostnames', 'POST', { hostname: 'second.example.test' })).data.error, 'hostname_limit_reached');
  assert.equal((await session.c.call('/api/keys', 'POST', { scopes: ['status:read'], password })).data.error, 'plan_required');
  assert.equal((await session.c.call('/api/hostnames/app.example.test/connect-token', 'POST')).status, 429);
  // Designed behavior: a pending open registration already holds its user and trial tenant, so its unexpired
  // link (one hour) still completes verification after rollback. The trial limits come from the tenant, not the flag.
  const pendingPassword = fakeSecret();
  assert.equal((await portal.client.call('/api/verify-email', 'POST', { token: linkToken(mail('pending@example.test')[0]), password: pendingPassword })).status, 200);
  const pending = await login(portal.port, 'pending@example.test', pendingPassword);
  assert.equal(pending.status, 200);
  assert.deepEqual({ ...(await pending.c.call('/api/me')).data.tenant, id: undefined }, { id: undefined, plan: 'trial', hostname_limit: 1 });
  assert.equal((await pending.c.call('/api/hostnames', 'POST', { hostname: 'pending.example.test' })).status, 201);
  assert.equal((await pending.c.call('/api/hostnames', 'POST', { hostname: 'more.example.test' })).data.error, 'hostname_limit_reached');
  assert.equal((await pending.c.call('/api/hostnames/pending.example.test/verify', 'POST')).status, 200);
  for (let i = 0; i < 3; i++) assert.equal((await pending.c.call('/api/hostnames/pending.example.test/connect-token', 'POST')).status, 201);
  assert.equal((await pending.c.call('/api/hostnames/pending.example.test/connect-token', 'POST')).status, 429);
  // Invites keep working after rollback.
  const code = createInvites({ dataDir }).mint({ email: 'invited@example.test' });
  assert.equal((await portal.client.call('/api/signup', 'POST', { email: 'invited@example.test', password: fakeSecret(), invite_code: code, accept_terms: true })).status, 200);
  assert.equal(accounts().users.filter((u) => u.email === 'invited@example.test').length, 1);
  assert.equal(accounts().tenants.find((x) => x.id === accounts().users.find((u) => u.email === 'invited@example.test').tenant_id).source, undefined);
  await portal.stop();
});
