import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixture, fakeSecret, request, tids } from './helpers.js';
import { createEdgeClient } from '../src/edge-client.js';
import { internalHarness } from '../../test/helpers/internal.js';

const cli = fileURLToPath(new URL('../bin/tenant.js', import.meta.url));
const edgeUrl = 'https://edge.example-edge.test';
const host = 'app.example.test';

function run(env, ...args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH, NODE_OPTIONS: process.env.NODE_OPTIONS ?? '', ...env } },
      (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr, json: (() => { try { return JSON.parse(stdout); } catch { return null; } })() }));
  });
}

// Portal wired to the real edge internal API on 127.0.0.1 (fake DNS and agent registry only).
async function setup(t) {
  const h = await internalHarness(t);
  const internalUrl = `http://127.0.0.1:${h.server.address().port}`;
  const f = await fixture(t, { edgeUrl }, { edge: createEdgeClient({ baseUrl: internalUrl, portalKey: h.portalKey }) });
  // The CLI stamps the real clock.
  f.advance(Date.now() - f.now());
  await f.client.call('/api/me');
  const a = await f.seed();
  const b = await f.seed(1);
  const created = await a.client.call('/api/hostnames', 'POST', { hostname: host });
  assert.equal(created.status, 201);
  h.prove(created.data);
  assert.equal((await a.client.call(`/api/hostnames/${host}/verify`, 'POST')).data.status, 'active');
  const key = (await a.client.call('/api/keys', 'POST', { password: a.password, scopes: ['status:read'] })).data.key;
  const token = (await a.client.call(`/api/hostnames/${host}/connect-token`, 'POST')).data.token;
  h.closed.length = 0;
  const env = { STATE_DIRECTORY: f.dataDir, EDGE_INTERNAL_URL: internalUrl, PORTAL_KEY: h.portalKey };
  const edgeFile = (name) => JSON.parse(readFileSync(join(h.dataDir, name), 'utf8'));
  const ask = async (name = host) => (await h.request(`/tls/ask?domain=${name}`)).status;
  const useKey = () => request(f.port, `/api/v1/hostnames/${host}`, { headers: { authorization: `Bearer ${key}` } });
  const useToken = () => request(f.port, '/api/connect/v1/hostname', { headers: { authorization: `Bearer ${token}` } });
  // After a CLI run, move the portal clock past the CLI's real-clock stamp.
  const catchUp = () => f.advance(Date.now() - f.now() + 1);
  const login = async (user, password) => {
    const client = (await f.seed(2 + login.count++)).client;
    await client.call('/api/logout', 'POST');
    await client.call('/api/me');
    const result = await client.call('/api/login', 'POST', { email: user.email, password });
    await client.call('/api/me');
    return { client, status: result.status, data: result.data };
  };
  login.count = 0;
  return { h, f, a, b, key, token, env, edgeFile, ask, useKey, useToken, catchUp, login };
}

test('suspend calls the real edge: credentials invalidated, tunnels closed, TLS ask refused; portal access ends', async (t) => {
  const s = await setup(t);
  const { h, f, a, b } = s;
  assert.equal(await s.ask(), 200);
  assert.ok(s.edgeFile('agent-credentials.json').some((c) => c.tenant_id === tids[0]));
  assert.ok(s.edgeFile('tunnel_hosts.json').includes(host));
  assert.equal((await s.useKey()).status, 200);
  assert.equal((await s.useToken()).status, 200);

  const first = await run(s.env, 'suspend', a.user.email.toUpperCase(), '--reason', 'abuse report');
  assert.equal(first.code, 0, first.stderr);
  assert.deepEqual(first.json, { action: 'suspend', tenant_id: tids[0], changed: true,
    pending_revocation: { sessions: 1, api_keys: 1, connect_tokens: 1 }, edge: 'ok', hostnames_suspended: 1 });
  assert.equal(statSync(join(f.dataDir, 'suspensions.json')).mode & 0o777, 0o600);
  for (const secret of [h.portalKey, s.key, s.token]) assert.equal(first.stdout.includes(secret) || first.stderr.includes(secret), false);
  // Edge: agent credentials gone, tunnel route dropped and the agent closed, TLS ask refused.
  assert.equal(s.edgeFile('agent-credentials.json').some((c) => c.tenant_id === tids[0]), false);
  assert.equal(s.edgeFile('tunnel_hosts.json').includes(host), false);
  assert.deepEqual(h.closed, [host]);
  assert.equal(await s.ask(), 404);
  assert.deepEqual(s.edgeFile('tenant_hostnames.json').map((c) => [c.tenant_id, c.status, c.suspension_reason, c.expires_at]),
    [[tids[0], 'suspended', 'administrative', null]]);

  // Portal: session, key and token refused and revoked.
  assert.equal((await a.client.call('/api/me')).data.email, null);
  assert.equal(f.store.read('sessions', []).some((x) => x.user_id === a.user.id), false);
  assert.equal((await s.useKey()).status, 401);
  assert.ok(f.store.read('api_keys', []).every((k) => k.tenant_id !== tids[0] || k.revoked_at));
  assert.equal((await s.useToken()).status, 401);
  // Login: same answer as a wrong password. Reset and sign-up: generic, nothing sent.
  const refused = await s.login(a.user, a.password);
  const wrong = await s.login(b.user, fakeSecret());
  assert.equal(refused.status, 401);
  assert.deepEqual(refused.data, wrong.data);
  const sent = f.messages.length;
  assert.deepEqual((await refused.client.call('/api/password-reset', 'POST', { email: a.user.email })).data, { ok: true });
  assert.deepEqual((await refused.client.call('/api/signup', 'POST', { email: a.user.email, password: fakeSecret(), accept_terms: true })).data, { ok: true });
  assert.equal(f.messages.length, sent);
  assert.equal((await b.client.call('/api/hostnames')).status, 200);

  // Idempotent: the entry is kept as first written; the edge is called again and reports nothing new.
  const before = f.store.read('suspensions');
  const again = await run(s.env, 'suspend', tids[0], '--reason', 'abuse report');
  assert.equal(again.code, 0);
  assert.deepEqual([again.json.changed, again.json.edge, again.json.hostnames_suspended], [false, 'ok', 0]);
  assert.deepEqual(f.store.read('suspensions'), before);
  assert.equal(h.logs.filter(([e]) => e.route === '/internal/v1/tenants/:tid/suspend' && e.status === 200).length, 2);
});

test('resume with no credential use during the suspension keeps old sessions, keys and tokens dead', async (t) => {
  const s = await setup(t);
  const { f, a } = s;
  assert.equal((await run(s.env, 'suspend', tids[0], '--reason', 'abuse report')).code, 0);
  // Nothing touches the portal while suspended.
  const resumed = await run(s.env, 'resume', tids[0], '--reason', 'resolved');
  assert.equal(resumed.code, 0, resumed.stderr);
  assert.equal(resumed.json.changed, true);
  assert.match(resumed.json.note, /release/);
  assert.equal((await run(s.env, 'resume', tids[0], '--reason', 'resolved')).json.changed, false);
  s.catchUp();
  assert.equal((await a.client.call('/api/me')).data.email, null);
  assert.equal((await a.client.call('/api/hostnames')).status, 401);
  assert.equal((await s.useKey()).status, 401);
  assert.equal((await s.useToken()).status, 401);
  // A fresh login works, and so does a key issued after resume.
  const fresh = await s.login(a.user, a.password);
  assert.equal(fresh.status, 200);
  assert.equal((await fresh.client.call('/api/me')).data.email, a.user.email);
  const key = (await fresh.client.call('/api/keys', 'POST', { password: a.password, scopes: ['status:read'] })).data.key;
  assert.equal((await request(f.port, `/api/v1/hostnames/${host}`, { headers: { authorization: `Bearer ${key}` } })).status, 200);
  // The old key still fails after the new one works.
  assert.equal((await s.useKey()).status, 401);
  // A second suspension moves the epoch: the post-resume key dies too.
  assert.equal((await run(s.env, 'suspend', tids[0], '--reason', 'again')).json.changed, true);
  assert.equal((await run(s.env, 'resume', tids[0], '--reason', 'resolved')).json.changed, true);
  s.catchUp();
  assert.equal((await request(f.port, `/api/v1/hostnames/${host}`, { headers: { authorization: `Bearer ${key}` } })).status, 401);
});

test('suspended hostnames stay reserved for every other account until an admin release after resume', async (t) => {
  const s = await setup(t);
  const { h, f, a, b } = s;
  assert.equal((await run(s.env, 'suspend', tids[0], '--reason', 'abuse report')).code, 0);
  const claim = () => b.client.call('/api/hostnames', 'POST', { hostname: host });
  assert.deepEqual((await claim()).data, { error: 'hostname_unavailable' });
  // Release refuses while the account is suspended and does not call the edge.
  const early = await run(s.env, 'release', tids[0], '--reason', 'ticket closed');
  assert.equal(early.code, 1);
  assert.match(early.stderr, /still suspended/);
  assert.equal(h.logs.some(([e]) => e.route === '/internal/v1/tenants/:tid/release'), false);
  // Reservations never expire.
  h.clock.advance(30 * 86400000);
  assert.equal((await claim()).status, 409);
  assert.equal((await run(s.env, 'resume', tids[0], '--reason', 'resolved')).code, 0);
  s.catchUp();
  assert.equal((await claim()).status, 409);
  const owner = (await s.login(a.user, a.password)).client;
  assert.deepEqual((await owner.call(`/api/hostnames/${host}/verify`, 'POST')).data, { error: 'administratively_suspended' });

  const released = await run(s.env, 'release', a.user.email, '--reason', 'ticket closed');
  assert.equal(released.code, 0, released.stderr);
  assert.deepEqual(released.json, { action: 'release', tenant_id: tids[0], changed: true, edge: 'ok', hostnames_released: 1 });
  for (const secret of [h.portalKey, s.key, s.token]) assert.equal(released.stdout.includes(secret), false);
  const again = await run(s.env, 'release', tids[0], '--reason', 'ticket closed');
  assert.deepEqual([again.code, again.json.changed, again.json.hostnames_released], [0, false, 0]);
  // Another account can now claim and verify it; TLS follows the new owner.
  const taken = await claim();
  assert.equal(taken.status, 201);
  h.prove(taken.data);
  assert.equal((await b.client.call(`/api/hostnames/${host}/verify`, 'POST')).data.status, 'active');
  assert.equal(await s.ask(), 200);
  assert.deepEqual(f.store.read('admin_audit', []).map((e) => [e.action, e.changed, e.edge ?? null]),
    [['suspend', true, 'ok'], ['resume', true, null], ['release', true, 'ok'], ['release', false, 'ok']]);
});

test('edge failures keep the portal suspension and exit 2 without printing secrets', async (t) => {
  const s = await setup(t);
  const bad = fakeSecret();
  const result = await run({ ...s.env, PORTAL_KEY: bad }, 'suspend', tids[0], '--reason', 'abuse report');
  assert.equal(result.code, 2);
  assert.deepEqual([result.json.edge, result.json.changed], ['failed', true]);
  for (const secret of [bad, s.h.portalKey, s.key, s.token]) assert.equal(result.stdout.includes(secret) || result.stderr.includes(secret), false);
  assert.equal(s.h.logs.at(-1)[0].status, 401);
  assert.equal(await s.ask(), 200, 'the real edge refused the wrong key');
  assert.equal((await s.useKey()).status, 401);
  assert.equal((await s.a.client.call('/api/hostnames')).status, 401);
  assert.equal(s.f.store.read('admin_audit', [])[0].edge, 'failed');
  const missing = await run({ STATE_DIRECTORY: s.f.dataDir, EDGE_INTERNAL_URL: s.env.EDGE_INTERNAL_URL }, 'suspend', tids[0], '--reason', 'abuse report');
  assert.deepEqual([missing.code, missing.json.edge], [2, 'failed']);
  // The retry with the right key reaches the edge.
  const retry = await run(s.env, 'suspend', tids[0], '--reason', 'abuse report');
  assert.deepEqual([retry.code, retry.json.changed, retry.json.edge, retry.json.hostnames_suspended], [0, false, 'ok', 1]);
  assert.equal(await s.ask(), 404);
  // Release with a bad key fails the same way and keeps the reservation.
  await run(s.env, 'resume', tids[0], '--reason', 'resolved');
  const denied = await run({ ...s.env, PORTAL_KEY: bad }, 'release', tids[0], '--reason', 'ticket closed');
  assert.deepEqual([denied.code, denied.json.edge, denied.json.changed], [2, 'failed', false]);
  assert.equal(s.edgeFile('tenant_hostnames.json').length, 1);
});

test('the CLI refuses bad arguments and unknown tenants without writing state', async (t) => {
  const s = await setup(t);
  for (const args of [[], ['suspend', tids[0]], ['suspend', tids[0], '--reason', ''], ['pause', tids[0], '--reason', 'x'],
    ['release', tids[0]], ['suspend', tids[0], '--reason', 'x', '--force']]) assert.equal((await run(s.env, ...args)).code, 1, JSON.stringify(args));
  assert.equal((await run(s.env, 'suspend', 'nobody@example.test', '--reason', 'x')).code, 1);
  assert.equal((await run(s.env, 'release', 't_zzzzzzzzzzzzzzzzzzzz', '--reason', 'x')).code, 1);
  assert.equal((await run({ ...s.env, STATE_DIRECTORY: '' }, 'suspend', tids[0], '--reason', 'x')).code, 1);
  assert.equal(s.f.store.read('suspensions', null), null);
  assert.equal(s.h.logs.some(([e]) => /suspend|release/.test(e.route ?? '')), false);
  assert.equal((await s.useKey()).status, 200);
});

test('the portal refuses hostname create, verify, rotate and connect tokens for a suspended account', async (t) => {
  const f = await fixture(t, { edgeUrl });
  const a = await f.seed();
  await a.client.call('/api/hostnames', 'POST', { hostname: host });
  await a.client.call(`/api/hostnames/${host}/verify`, 'POST');
  const key = (await a.client.call('/api/keys', 'POST', { password: a.password, scopes: ['hostnames:create', 'connect'] })).data.key;
  const bearer = { authorization: `Bearer ${key}`, 'content-type': 'application/json' };
  const suspend = () => f.store.write('suspensions', { tenants: { [tids[0]]: { at: new Date(f.now()).toISOString(), reason: 'x', revoked_before: f.now() } } });
  const mutations = () => f.calls.filter(([name]) => ['create', 'verify', 'rotate'].includes(name)).length;
  // Suspended between authentication and the edge call (the edge lookup before issuing/rotating is the window).
  const getHostname = f.edge.getHostname;
  f.edge.getHostname = async (...args) => { const result = await getHostname(...args); if (f.suspendOnLookup) suspend(); return result; };
  f.suspendOnLookup = true;
  const before = mutations();
  assert.equal((await a.client.call(`/api/hostnames/${host}/connect-token`, 'POST')).status, 401);
  assert.equal(f.store.read('connect_tokens', []).length, 0);
  f.store.write('suspensions', { tenants: {} });
  assert.equal((await request(f.port, `/api/v1/hostnames/${host}/connect`, { method: 'POST', headers: bearer, body: { origin: 'http://127.0.0.1:3000' } })).status, 401);
  assert.equal(mutations(), before);
  f.suspendOnLookup = false;
  // Plain suspension: every create, verify and connect route is refused before the edge is called.
  suspend();
  const session = [[`/api/hostnames`, { hostname: 'two.example.test' }], [`/api/hostnames/${host}/verify`], [`/api/hostnames/${host}/connect-token`],
    [`/api/hostnames/${host}/rotate`]];
  for (const [path, body] of session) assert.equal((await a.client.call(path, 'POST', body)).status, 401, path);
  for (const [path, body] of [['/api/v1/hostnames', { hostname: 'two.example.test' }], [`/api/v1/hostnames/${host}/verify`, {}], [`/api/v1/hostnames/${host}/connect`, { origin: 'http://127.0.0.1:3000' }]]) {
    assert.equal((await request(f.port, path, { method: 'POST', headers: bearer, body })).status, 401, path);
  }
  assert.equal(mutations(), before);
});

const linkToken = (message) => new URLSearchParams(new URL(message.link).hash.slice(1)).get('token');
const suspendAt = (f, tid, at, resumed) => f.store.write('suspensions', { tenants: { [tid]: { at: new Date(at).toISOString(), reason: 'x', revoked_before: at,
  ...(resumed ? { resumed_at: new Date(resumed).toISOString() } : {}) } } });

test('reset links issued before a suspension stay dead after resume', async (t) => {
  const f = await fixture(t);
  const a = await f.seed();
  await a.client.call('/api/password-reset', 'POST', { email: a.user.email });
  const old = linkToken(f.messages.at(-1));
  f.advance(1000);
  suspendAt(f, tids[0], f.now(), f.now() + 1);
  f.advance(1000);
  const next = fakeSecret();
  assert.equal((await a.client.call('/api/password-reset/confirm', 'POST', { token: old, password: next })).status, 401);
  // A link issued after resume works.
  await a.client.call('/api/password-reset', 'POST', { email: a.user.email });
  assert.equal((await a.client.call('/api/password-reset/confirm', 'POST', { token: linkToken(f.messages.at(-1)), password: next })).status, 200);
});

test('signup does not reclaim or mail a suspended unverified open account', async (t) => {
  const f = await fixture(t, { openSignup: true });
  const body = { email: 'held@example.test', password: fakeSecret(), accept_terms: true };
  await f.client.call('/api/signup', 'POST', body);
  assert.equal(f.messages.length, 1);
  const tid = f.store.read('accounts').tenants.find((x) => x.source === 'open').id;
  f.advance(3600001);
  suspendAt(f, tid, f.now());
  await f.client.call('/api/me');
  assert.deepEqual((await f.client.call('/api/signup', 'POST', body)).data, { ok: true });
  assert.equal(f.messages.length, 1);
});
