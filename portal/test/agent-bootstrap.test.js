// Agent bootstrap in the portal (milestone 4), against the real edge internal API (bootstrap enabled) and the real
// issuer-check listener over loopback. Issuance, status, cancel, Revoke agent and owner confirmation, with CSRF and Origin
// checks, plus revocation through the issuer check (key deletion, password reset, connect-token DELETE, logout).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { once } from 'node:events';
import { randomBytes, randomUUID } from 'node:crypto';
import { fixture, request, origin, tids, linkToken, temporary } from './helpers.js';
import { createEdgeClient } from '../src/edge-client.js';
import { createIssuerCheckServer } from '../src/issuer-check.js';
import { createIssuerValidator, createAgentBootstrap, sessionIssuerId } from '../src/agent-bootstrap.js';
import { createStore } from '../src/store.js';
import { createRateLimits } from '../src/rate-limits.js';
import { createSuspensions } from '../src/suspensions.js';
import { internalHarness } from '../../test/helpers/internal.js';
import { createBootstrap } from '../../src/onboard/bootstrap.js';
import { createIssuerChecker } from '../../src/onboard/issuer-check.js';
import { validCredential } from '../../src/onboard/credentials.js';
import { readJson } from '../../src/onboard/json.js';
import { generateKey, signExchange, sha256 } from '../../agent/protocol.js';

const host = 'app.example.test', audience = 'https://edge.example.test', upstream = 'http://127.0.0.1:3000', edgeUrl = 'https://edge.example-edge.test';
const bearer = (token) => ({ authorization: `Bearer ${token}`, 'content-type': 'application/json' });
const key = generateKey();

// Portal (flag on) -> real edge client -> real internal server with bootstrap enabled; the edge's issuer check goes
// through the authenticated client to the portal's own issuer-check listener over loopback.
async function setup(t, { flag = true } = {}) {
  const dataDir = temporary(t);
  let checker;
  const service = createBootstrap({ bootstrapEnabled: true, bootstrapAudience: audience, dataDir, now: Date.now,
    issuerCheck: (issuer, opts) => checker.check(issuer, opts), registry: { closeCandidates() {}, confirmCandidate: () => 'not_ready' } });
  t.after(() => service.close());
  const h = await internalHarness(t, { dataDir, now: Date.now, bootstrap: service });
  const f = await fixture(t, { edgeUrl, ...(flag ? { agentBootstrap: true } : {}) }, { edge: createEdgeClient({ baseUrl: `http://127.0.0.1:${h.server.address().port}`, portalKey: h.portalKey }) });
  f.advance(Date.now() - f.now());
  const secret = randomBytes(32).toString('hex');
  const listener = createIssuerCheckServer({ secret, validate: createIssuerValidator({ store: f.store, now: f.now }) });
  listener.listen(0, '127.0.0.1'); await once(listener, 'listening');
  t.after(() => new Promise((resolve) => { listener.closeAllConnections(); listener.close(resolve); }));
  checker = createIssuerChecker({ url: `http://127.0.0.1:${listener.address().port}/internal/v1/issuer-check`, secret });
  const a = await f.seed();
  const created = await a.client.call('/api/hostnames', 'POST', { hostname: host });
  h.prove(created.data);
  const verified = await a.client.call(`/api/hostnames/${host}/verify`, 'POST');
  assert.equal(verified.data.status, 'active');
  h.closed.length = 0;
  const activeToken = verified.data.credential.token;
  async function redeem(issued, k = key) {
    const body = { hostname: host, origin: issued.origin, deployment_id: issued.deployment_id, request_id: randomUUID(), recipient_public_key: k.publicKey, agent_version: '1.2.3' };
    body.proof = signExchange(k.privateKey, audience, sha256(issued.code), body);
    try { return { status: 200, body: await service.exchange(issued.code, body, '127.0.0.1') }; } catch (e) { return { status: e.status, body: { error: e.code } }; }
  }
  const issue = (client = a.client, body = { origin: upstream }, overrides) => client.call(`/api/hostnames/${host}/bootstraps`, 'POST', body, overrides);
  const edgeStatus = (id) => service.status(tids[0], host, id).status;
  const activeValid = () => validCredential(activeToken, host, h.dataDir, Date.now);
  return { f, h, a, service, redeem, issue, edgeStatus, activeToken, activeValid };
}

function files(dir) {
  return readdirSync(dir).flatMap((name) => { const p = join(dir, name); return statSync(p).isDirectory() ? files(p) : [p]; });
}

test('session issuance needs a verified session, the CSRF token and the exact Origin; the code is shown once, never stored', async (t) => {
  const s = await setup(t);
  assert.equal((await s.issue(s.a.client, { origin: upstream }, { 'x-fd-csrf': '' })).status, 401);
  assert.equal((await s.issue(s.a.client, { origin: upstream }, { origin: 'https://evil.example.test' })).status, 401);
  assert.equal((await s.issue(s.a.client, { origin: upstream }, { origin: `${origin}.evil.test` })).status, 401);
  assert.equal((await request(s.f.port, `/api/hostnames/${host}/bootstraps`, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: { origin: upstream } })).status, 401);
  const unverified = await s.f.seed(1, false);
  assert.equal((await s.issue(unverified.client)).status, 401);
  const stranger = await s.f.seed(2);
  assert.deepEqual((await s.issue(stranger.client)).data, { error: 'hostname_not_found' });
  assert.equal((await s.issue(s.a.client, { origin: 'http://203.0.113.9:80' })).status, 400);
  assert.equal((await s.issue(s.a.client, {})).status, 400);

  const issued = await s.issue();
  assert.equal(issued.status, 201);
  assert.equal(issued.headers['cache-control'], 'no-store');
  assert.match(issued.data.code, /^fdab_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(Object.keys(issued.data).sort(), ['code', 'deployment_id', 'expires_at', 'hostname', 'issuance_id', 'note', 'origin']);
  assert.equal(issued.data.origin, upstream);
  for (const file of files(s.f.dataDir)) assert.ok(!readFileSync(file, 'utf8').includes(issued.data.code), `code stored in ${file}`);
  const list = await s.a.client.call(`/api/hostnames/${host}/bootstraps`);
  assert.equal(list.status, 200);
  assert.equal(list.text.includes('fdab_'), false);
  assert.deepEqual(list.data.bootstraps.map((b) => [b.issuance_id, b.issuer_kind, b.state, b.status]), [[issued.data.issuance_id, 'session', 'issued', 'pending']]);
  assert.equal((await stranger.client.call(`/api/hostnames/${host}/bootstraps`)).status, 404);
  // The issuance used the session issuer and is accepted by the edge's authenticated issuer check.
  const redeemed = await s.redeem(issued.data);
  assert.equal(redeemed.status, 200);
  assert.equal(s.edgeStatus(issued.data.issuance_id), 'used');
  assert.ok(s.activeValid(), 'exchange alone leaves the active credential');
  // Signing out ends the session issuer: a fresh code from that session is refused at exchange.
  const second = await s.issue();
  await s.a.client.call('/api/logout', 'POST');
  assert.equal((await s.redeem(second.data)).status, 401);
});

test('cancel needs CSRF and refuses the code at the edge; cancel-by-reissue is limited before any edge mutation', async (t) => {
  const s = await setup(t);
  const first = (await s.issue()).data;
  assert.equal((await s.a.client.call(`/api/hostnames/${host}/bootstraps`, 'DELETE', undefined, { 'x-fd-csrf': '' })).status, 401);
  assert.deepEqual((await s.a.client.call(`/api/hostnames/${host}/bootstraps`, 'DELETE')).data, { cancelled: true });
  assert.equal(s.edgeStatus(first.issuance_id), 'cancelled');
  assert.equal((await s.redeem(first)).status, 401);
  assert.ok(s.activeValid());
  // Three reissues that cancel a pending code are allowed in an hour; the fourth is refused while the old code stays pending.
  const issued = [];
  for (let i = 0; i < 4; i++) { const r = await s.issue(); assert.equal(r.status, 201, `issue ${i}`); issued.push(r.data); }
  const refused = await s.issue();
  assert.equal(refused.status, 429);
  assert.ok(refused.data.retry_after <= 3600);
  assert.equal(s.edgeStatus(issued.at(-1).issuance_id), 'pending', 'the 429 happened before any edge mutation');
  assert.equal((await s.redeem(issued.at(-1))).status, 200);
});

test('cancel-by-reissue allows 3 per hour and 6 per UTC day per principal across hostnames', async (t) => {
  const store = createStore(temporary(t)); let time = Date.parse('2026-03-01T00:00:00Z'); const now = () => time;
  const edge = { getHostname: async () => ({ status: 'active' }), getBootstrap: async () => ({ status: 'pending' }),
    issueBootstrap: async () => ({ code: 'fdab_synthetic', origin: upstream, expires_at: new Date(time + 900000).toISOString() }) };
  const service = createAgentBootstrap({ store, edge, limits: createRateLimits(now, store), now });
  const issue = (hostname) => service.issue({ tid: tids[0], hostname, origin: upstream, principal: 'user-0', issuer: { kind: 'session', id: 's', authorization_generation: 1 } });
  const a = 'a.example.test', b = 'b.example.test';
  // Hour 1: the first code per host cancels nothing; three cancelling reissues, the fourth is refused.
  await issue(a); await issue(b);
  await issue(a); await issue(b); await issue(a);
  await assert.rejects(issue(b), { code: 'rate_limited', retry_after: 3600 });
  // Hour 2 (earlier codes expired after 15 minutes): two more cancelling reissues (5 today).
  time += 3600000; await issue(a); await issue(a); await issue(a);
  // Hour 3: the sixth cancelling reissue of the day passes, the seventh is refused by the daily budget.
  time += 3600000; await issue(b); await issue(b);
  await assert.rejects(issue(b), (e) => e.code === 'rate_limited' && e.retry_after > 3600);
  // Issuance that cancels nothing is not limited by these budgets.
  await issue('c.example.test');
});

test('API keys issue with the connect scope only; key deletion and password reset invalidate pending issuance', async (t) => {
  const s = await setup(t);
  const makeKey = async (scopes) => (await s.a.client.call('/api/keys', 'POST', { password: s.a.password, scopes })).data;
  const connect = await makeKey(['connect']); const status = await makeKey(['status:read']);
  const viaKey = (secret, body = { origin: upstream }) => request(s.f.port, `/api/v1/hostnames/${host}/bootstraps`, { method: 'POST', headers: bearer(secret), body });
  assert.equal((await viaKey(status.key)).status, 403);
  assert.equal((await request(s.f.port, `/api/v1/hostnames/${host}/bootstraps`, { headers: bearer(connect.key) })).status, 405);
  assert.equal((await viaKey(connect.key, { origin: 'nope' })).status, 400);
  const issued = await viaKey(connect.key);
  assert.equal(issued.status, 201);
  assert.match(issued.data.code, /^fdab_/);
  assert.equal((await s.a.client.call(`/api/hostnames/${host}/bootstraps`)).data.bootstraps[0].issuer_kind, 'api_key');
  assert.equal((await s.a.client.call(`/api/keys/${connect.id}`, 'DELETE')).status, 200);
  assert.equal((await s.redeem(issued.data)).status, 401, 'deleted key');

  const other = await makeKey(['connect']);
  const pending = (await viaKey(other.key)).data;
  await s.a.client.call('/api/password-reset', 'POST', { email: s.a.user.email });
  const reset = await s.a.client.call('/api/password-reset/confirm', 'POST', { token: linkToken(s.f.messages.at(-1)), password: `New-${randomBytes(12).toString('hex')}` });
  assert.equal(reset.status, 200);
  assert.equal((await s.redeem(pending)).status, 401, 'password reset');
});

test('trial tenants issue through sessions and connect tokens but never API keys', async (t) => {
  const s = await setup(t);
  const key = (await s.a.client.call('/api/keys', 'POST', { password: s.a.password, scopes: ['connect'] })).data.key;
  const accounts = s.f.store.read('accounts'); Object.assign(accounts.tenants[0], { plan: 'trial', source: 'open', hostname_limit: 1 }); s.f.store.write('accounts', accounts);
  assert.equal((await request(s.f.port, `/api/v1/hostnames/${host}/bootstraps`, { method: 'POST', headers: bearer(key), body: { origin: upstream } })).status, 401);
  assert.equal((await s.issue()).status, 201);
  const token = (await s.a.client.call(`/api/hostnames/${host}/connect-token`, 'POST')).data.token;
  assert.equal((await request(s.f.port, '/api/connect/v1/bootstrap', { method: 'POST', headers: bearer(token), body: { origin: upstream } })).status, 201);
});

test('connect tokens issue once; DELETE cancels their pending bootstrap and candidate but leaves the connected agent', async (t) => {
  const s = await setup(t);
  const token = (await s.a.client.call(`/api/hostnames/${host}/connect-token`, 'POST')).data.token;
  const viaToken = (body = { origin: upstream }) => request(s.f.port, '/api/connect/v1/bootstrap', { method: 'POST', headers: bearer(token), body });
  assert.equal((await viaToken({ origin: 'http://203.0.113.9:80' })).status, 400);
  const issued = await viaToken();
  assert.equal(issued.status, 201);
  assert.equal((await viaToken()).status, 409, 'one command per token');
  assert.equal((await request(s.f.port, '/api/connect/v1/hostname', { headers: bearer(token) })).data.command_issued, true);
  // Redeemed: a pending candidate credential exists next to the active one.
  const redeemed = await s.redeem(issued.data);
  assert.equal(redeemed.status, 200);
  const candidate = () => readJson('agent-credentials.json', [], s.h.dataDir).find((r) => r.id === redeemed.body.credential_id);
  assert.equal(candidate().revoked_at, null);
  const deleted = await s.a.client.call(`/api/hostnames/${host}/connect-token`, 'DELETE');
  assert.deepEqual(deleted.data, { revoked: 1, bootstraps_cancelled: true });
  assert.ok(candidate().revoked_at, 'pending candidate and recovery cancelled');
  assert.equal(s.edgeStatus(issued.data.issuance_id), 'cancelled');
  assert.deepEqual(s.h.closed, [], 'the connected agent is not closed');
  assert.ok(s.activeValid(), 'the active credential stays valid');
  // A matching retry (recovery) is refused too.
  assert.equal((await s.redeem(issued.data)).status, 401);
  // Without a token-issued bootstrap, DELETE cancels nothing at the edge.
  const own = (await s.issue()).data;
  assert.deepEqual((await s.a.client.call(`/api/hostnames/${host}/connect-token`, 'DELETE')).data, { revoked: 0, bootstraps_cancelled: false });
  assert.equal(s.edgeStatus(own.issuance_id), 'pending');
});

test('Revoke agent needs a session, CSRF, exact Origin and explicit confirmation; it revokes credentials and codes and mints nothing', async (t) => {
  const s = await setup(t);
  const pending = (await s.issue()).data;
  const revoke = (body = { confirm: true }, overrides) => s.a.client.call(`/api/hostnames/${host}/revoke-agent`, 'POST', body, overrides);
  assert.deepEqual((await revoke({})).data, { error: 'confirmation_required' });
  assert.equal((await revoke(undefined, { 'x-fd-csrf': '' })).status, 401);
  assert.equal((await revoke(undefined, { origin: 'https://evil.example.test' })).status, 401);
  assert.equal((await request(s.f.port, `/api/hostnames/${host}/revoke-agent`, { method: 'POST', headers: { origin, 'content-type': 'application/json' }, body: { confirm: true } })).status, 401);
  assert.equal((await s.a.client.call(`/api/hostnames/${host}/revoke-agent`)).status, 405);
  const stranger = await s.f.seed(1);
  assert.equal((await stranger.client.call(`/api/hostnames/${host}/revoke-agent`, 'POST', { confirm: true })).status, 404);
  assert.ok(s.activeValid());
  const before = readJson('agent-credentials.json', [], s.h.dataDir).length;
  assert.deepEqual((await revoke()).data, { hostname: host, revoked: true });
  assert.equal(s.activeValid(), false);
  assert.deepEqual(s.h.closed, [host]);
  assert.equal(s.edgeStatus(pending.issuance_id), 'cancelled');
  assert.equal((await s.redeem(pending)).status, 401);
  const after = readJson('agent-credentials.json', [], s.h.dataDir);
  assert.equal(after.length, before, 'no replacement credential');
  assert.ok(after.filter((r) => r.claim_hostname === host).every((r) => r.revoked_at));
});

test('owner confirmation is session-only, CSRF-protected and validates its input', async (t) => {
  const s = await setup(t);
  const path = (id) => `/api/hostnames/${host}/bootstraps/candidates/${id}/confirm`;
  const fp = 'a'.repeat(64);
  assert.equal((await s.a.client.call(path(randomUUID()), 'POST', { key_fingerprint: fp }, { 'x-fd-csrf': '' })).status, 401);
  assert.equal((await s.a.client.call(path(randomUUID()), 'POST', { key_fingerprint: 'nope' })).status, 400);
  assert.deepEqual((await s.a.client.call(path(randomUUID()), 'POST', { key_fingerprint: fp })).data, { error: 'candidate_not_found' });
  const key = (await s.a.client.call('/api/keys', 'POST', { password: s.a.password, scopes: ['connect'] })).data.key;
  assert.equal((await request(s.f.port, `/api/v1/hostnames/${host}/bootstraps/candidates/x/confirm`, { method: 'POST', headers: bearer(key), body: { key_fingerprint: fp } })).status, 404);
});

test('issuer validity covers suspension, verification, generation, expiry and revocation for every issuer kind', async (t) => {
  const s = await setup(t);
  const validate = createIssuerValidator({ store: s.f.store, now: s.f.now });
  const sessions = s.f.store.read('sessions').filter((x) => x.user_id === s.a.user.id);
  const session = { issuer_kind: 'session', issuer_id: sessionIssuerId(sessions[0]), authorization_generation: s.a.user.auth_version };
  assert.equal(validate(session), true);
  assert.equal(validate({ ...session, authorization_generation: 2 }), false);
  assert.equal(validate({ ...session, issuer_id: 'unknown' }), false);
  assert.equal(validate({ ...session, issuer_kind: 'operator' }), false);
  const token = (await s.a.client.call(`/api/hostnames/${host}/connect-token`, 'POST')).data;
  const tokenIssuer = { issuer_kind: 'connect_token', issuer_id: token.id, authorization_generation: 1 };
  assert.equal(validate(tokenIssuer), true);
  const apiKey = (await s.a.client.call('/api/keys', 'POST', { password: s.a.password, scopes: ['connect'] })).data;
  const keyIssuer = { issuer_kind: 'api_key', issuer_id: apiKey.id, authorization_generation: 1 };
  assert.equal(validate(keyIssuer), true);
  assert.equal(validate({ ...keyIssuer, authorization_generation: '1' }), false);
  // Unverified email ends every issuer kind.
  const accounts = s.f.store.read('accounts'); accounts.users[0].email_verified_at = null; s.f.store.write('accounts', accounts);
  for (const issuer of [session, tokenIssuer, keyIssuer]) assert.equal(validate(issuer), false, issuer.issuer_kind);
  accounts.users[0].email_verified_at = new Date(s.f.now()).toISOString(); s.f.store.write('accounts', accounts);
  // Suspension ends every issuer kind, and after resume pre-suspension issuers stay dead.
  const suspensions = createSuspensions(s.f.store);
  suspensions.set(tids[0], { at: new Date(s.f.now()).toISOString(), reason: 'test', revoked_before: s.f.now() });
  for (const issuer of [session, tokenIssuer, keyIssuer]) assert.equal(validate(issuer), false, issuer.issuer_kind);
  s.f.advance(1000); suspensions.clear(tids[0], new Date(s.f.now()).toISOString());
  for (const issuer of [session, tokenIssuer, keyIssuer]) assert.equal(validate(issuer), false, `${issuer.issuer_kind} after resume`);
});

test('connect-token issuers expire with the token; a command-used token stays a valid issuer until then', async (t) => {
  const s = await setup(t);
  const token = (await s.a.client.call(`/api/hostnames/${host}/connect-token`, 'POST')).data;
  const validate = createIssuerValidator({ store: s.f.store, now: s.f.now });
  const issuer = { issuer_kind: 'connect_token', issuer_id: token.id, authorization_generation: 1 };
  assert.equal((await request(s.f.port, '/api/connect/v1/bootstrap', { method: 'POST', headers: bearer(token.token), body: { origin: upstream } })).status, 201);
  assert.equal(validate(issuer), true, 'used is expected');
  s.f.advance(3600000);
  assert.equal(validate(issuer), false, 'expired');
});

test('flag off: no bootstrap route, page, script or response field exists; the responses equal those for unknown paths', async (t) => {
  const s = await setup(t, { flag: false });
  const token = (await s.a.client.call(`/api/hostnames/${host}/connect-token`, 'POST')).data.token;
  const apiKey = (await s.a.client.call('/api/keys', 'POST', { password: s.a.password, scopes: ['connect'] })).data.key;
  const same = async (path, twin, opts = {}) => {
    const [a, b] = [await request(s.f.port, path, opts), await request(s.f.port, twin, opts)];
    assert.deepEqual([a.status, a.text, a.headers['content-type']], [b.status, b.text, b.headers['content-type']], path);
  };
  await same('/agent', '/agent-unknown');
  await same('/js/agent-bootstrap.js', '/js/agent-unknown.js');
  await same(`/api/v1/hostnames/${host}/bootstraps`, `/api/v1/hostnames/${host}/unknown`, { method: 'POST', headers: bearer(apiKey), body: { origin: upstream } });
  await same('/api/connect/v1/bootstrap', '/api/connect/v1/unknown', { method: 'POST', headers: bearer(token), body: { origin: upstream } });
  for (const [method, suffix] of [['GET', 'bootstraps'], ['POST', 'bootstraps'], ['DELETE', 'bootstraps'], ['POST', 'revoke-agent'], ['POST', 'bootstraps/candidates/x/confirm']]) {
    const [a, b] = [await s.a.client.call(`/api/hostnames/${host}/${suffix}`, method, method === 'GET' ? undefined : {}), await s.a.client.call(`/api/hostnames/${host}/unknown-${method}`, method, method === 'GET' ? undefined : {})];
    assert.deepEqual([a.status, a.data], [b.status, b.data], `${method} ${suffix}`);
  }
  assert.deepEqual((await s.a.client.call(`/api/hostnames/${host}/connect-token`, 'DELETE')).data, { revoked: 1 });
  assert.deepEqual(Object.keys((await s.a.client.call('/api/me')).data).sort(), ['csrf', 'email', 'email_verified', 'open_signup', 'tenant']);
  // Nothing reached the edge's bootstrap routes.
  assert.deepEqual(s.f.store.read('agent_bootstraps', []), []);
});

test('concurrent issuance serializes each hostname and enforces hourly and daily reissue budgets', async (t) => {
  const store = createStore(temporary(t)); let time = Date.parse('2026-03-01T00:00:00Z');
  const now = () => time; let calls = 0; const active = new Set();
  const edge = { getHostname: async () => ({ status: 'active' }), getBootstrap: async () => ({ status: 'pending' }),
    async issueBootstrap(_tid, hostname) {
      assert.equal(active.has(hostname), false, 'one in-flight issuance per hostname');
      active.add(hostname); calls++;
      await new Promise((resolve) => setImmediate(resolve));
      active.delete(hostname);
      return { origin: upstream, expires_at: new Date(time + 900000).toISOString() };
    } };
  const service = createAgentBootstrap({ store, edge, limits: createRateLimits(now, store), now });
  const issue = (hostname) => service.issue({ tid: tids[0], hostname, origin: upstream, principal: 'user-0',
    issuer: { kind: 'session', id: 's', authorization_generation: 1 } });
  const batch = async (hosts, successes) => {
    const before = calls;
    const results = await Promise.allSettled(hosts.map(issue));
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, successes);
    for (const r of results.filter((r) => r.status === 'rejected')) assert.equal(r.reason.code, 'rate_limited');
    assert.equal(calls - before, successes, 'refusals never mutate the edge');
  };
  await batch(Array(6).fill(host), 4); // First issuance plus three hourly replacements.
  time += 3600000;
  await batch(Array(3).fill(host), 3); // Two more replacements: five today.
  time += 3600000;
  const hosts = ['a.example.test', 'b.example.test', 'c.example.test'];
  await batch(hosts, 3);
  await batch(hosts.flatMap((h) => [h, h]), 1); // Only the sixth daily replacement passes.
});

test('unresolved requested and uncertain reservations consume reissue budgets after restart', async (t) => {
  for (const state of ['requested', 'uncertain']) {
    const store = createStore(temporary(t)); const time = Date.parse('2026-03-01T00:00:00Z'); const now = () => time;
    store.write('agent_bootstraps', [{ issuance_id: randomUUID(), tenant_id: tids[0], hostname: host,
      created_at: new Date(time).toISOString(), state }]);
    let calls = 0;
    const edge = { getHostname: async () => ({ status: 'active' }),
      getBootstrap: async () => { throw new Error('unavailable'); },
      issueBootstrap: async () => { calls++; throw new Error('unavailable'); } };
    const service = createAgentBootstrap({ store, edge, limits: createRateLimits(now, store), now });
    const issue = () => service.issue({ tid: tids[0], hostname: host, origin: upstream, principal: 'user-0',
      issuer: { kind: 'session', id: 's', authorization_generation: 1 } });
    const results = await Promise.allSettled(Array.from({ length: 5 }, issue));
    assert.equal(calls, 3);
    assert.equal(results.filter((r) => r.reason.code === 'rate_limited').length, 2);
    assert.equal(store.read('agent_bootstraps').filter((r) => r.state === 'requested').length, state === 'requested' ? 1 : 0);
  }
});
