import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFile } from 'node:child_process';
import { statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixture, fakeSecret, listen, request, tids } from './helpers.js';

const cli = fileURLToPath(new URL('../bin/tenant.js', import.meta.url));
const edgeUrl = 'https://edge.example-edge.test';

// Fake edge internal API on 127.0.0.1: records each call, answers /suspend with the tenant's hostnames.
async function fakeInternal(t, { status = 200 } = {}) {
  const calls = [];
  const server = http.createServer((req, res) => {
    calls.push({ method: req.method, url: req.url, key: req.headers['x-fastdog-portal-key'] });
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(status === 200 ? { tenant_id: req.url.split('/')[4], hostnames: ['app.example.test'] } : { error: 'internal_error' }));
  });
  return { calls, url: `http://127.0.0.1:${await listen(t, server)}` };
}

function run(env, ...args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH, NODE_OPTIONS: process.env.NODE_OPTIONS ?? '', ...env } },
      (error, stdout, stderr) => resolve({ code: error ? error.code : 0, stdout, stderr, json: (() => { try { return JSON.parse(stdout); } catch { return null; } })() }));
  });
}

async function setup(t, edgeOptions) {
  const f = await fixture(t, { edgeUrl });
  // The CLI counts live records against the real clock.
  f.advance(Date.now() - f.now());
  await f.client.call('/api/me');
  const a = await f.seed();
  const b = await f.seed(1);
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const key = (await a.client.call('/api/keys', 'POST', { password: a.password, scopes: ['status:read'] })).data.key;
  const token = (await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).data.token;
  const internal = await fakeInternal(t, edgeOptions);
  const portalKey = fakeSecret();
  const env = { STATE_DIRECTORY: f.dataDir, EDGE_INTERNAL_URL: internal.url, PORTAL_KEY: portalKey };
  const useKey = () => request(f.port, '/api/v1/hostnames/app.example.test', { headers: { authorization: `Bearer ${key}` } });
  const useToken = () => request(f.port, '/api/connect/v1/hostname', { headers: { authorization: `Bearer ${token}` } });
  return { f, a, b, key, token, internal, portalKey, env, useKey, useToken };
}

test('suspend blocks session, key, token, login and reset; resume restores login', async (t) => {
  const s = await setup(t);
  const { f, a, b } = s;
  assert.equal((await s.useKey()).status, 200);
  assert.equal((await s.useToken()).status, 200);

  const first = await run(s.env, 'suspend', a.user.email.toUpperCase(), '--reason', 'abuse report');
  assert.equal(first.code, 0, first.stderr);
  assert.deepEqual(first.json, { action: 'suspend', tenant_id: tids[0], changed: true,
    pending_revocation: { sessions: 1, api_keys: 1, connect_tokens: 1 }, edge: 'ok', hostnames_suspended: 1 });
  assert.deepEqual(s.internal.calls, [{ method: 'POST', url: `/internal/v1/tenants/${tids[0]}/suspend`, key: s.portalKey }]);
  assert.equal(statSync(join(f.dataDir, 'suspensions.json')).mode & 0o777, 0o600);
  for (const secret of [s.portalKey, s.key, s.token]) assert.equal(first.stdout.includes(secret) || first.stderr.includes(secret), false);

  // Session: identity is gone and the user's sessions are revoked.
  assert.equal((await a.client.call('/api/me')).data.email, null);
  assert.equal(f.store.read('sessions', []).some((x) => x.user_id === a.user.id), false);
  assert.equal((await a.client.call('/api/hostnames')).status, 401);
  // Key and token: refused and marked revoked.
  assert.equal((await s.useKey()).status, 401);
  assert.ok(f.store.read('api_keys', []).every((k) => k.tenant_id !== tids[0] || k.revoked_at));
  assert.equal((await s.useToken()).status, 401);
  assert.ok(f.store.read('connect_tokens', []).every((x) => x.tenant_id !== tids[0] || x.revoked_at));
  // Login: same answer as a wrong password.
  const fresh = (await f.seed(2)).client;
  await fresh.call('/api/logout', 'POST');
  await fresh.call('/api/me');
  const refused = await fresh.call('/api/login', 'POST', { email: a.user.email, password: a.password });
  const wrong = await fresh.call('/api/login', 'POST', { email: b.user.email, password: fakeSecret() });
  assert.equal(refused.status, 401);
  assert.deepEqual(refused.data, wrong.data);
  // Reset and sign-up: generic, nothing sent.
  const sent = f.messages.length;
  assert.deepEqual((await fresh.call('/api/password-reset', 'POST', { email: a.user.email })).data, { ok: true });
  assert.deepEqual((await fresh.call('/api/signup', 'POST', { email: a.user.email, password: fakeSecret() })).data, { ok: true });
  assert.equal(f.messages.length, sent);
  // Another tenant is untouched.
  assert.equal((await b.client.call('/api/hostnames')).status, 200);

  // Idempotent: the entry is kept as first written; the edge is retried.
  const before = f.store.read('suspensions');
  const again = await run(s.env, 'suspend', tids[0], '--reason', 'abuse report');
  assert.equal(again.code, 0);
  assert.equal(again.json.changed, false);
  assert.deepEqual(again.json.pending_revocation, { sessions: 0, api_keys: 0, connect_tokens: 0 });
  assert.deepEqual(f.store.read('suspensions'), before);

  const resumed = await run(s.env, 'resume', tids[0], '--reason', 'resolved');
  assert.equal(resumed.code, 0);
  assert.equal(resumed.json.changed, true);
  assert.match(resumed.json.note, /re-verifies/);
  assert.equal(s.internal.calls.length, 2, 'resume does not call the edge');
  assert.equal((await run(s.env, 'resume', tids[0], '--reason', 'resolved')).json.changed, false);
  await fresh.call('/api/logout', 'POST');
  await fresh.call('/api/me');
  assert.equal((await fresh.call('/api/login', 'POST', { email: a.user.email, password: a.password })).status, 200);
  assert.equal((await fresh.call('/api/me')).data.email, a.user.email);
  // Revoked credentials stay revoked after resume.
  assert.equal((await s.useKey()).status, 401);

  const audit = f.store.read('admin_audit', []);
  assert.deepEqual(audit.map((e) => [e.action, e.changed, e.edge ?? null]),
    [['suspend', true, 'ok'], ['suspend', false, 'ok'], ['resume', true, null], ['resume', false, null]]);
  assert.equal(JSON.stringify(audit).includes(s.portalKey), false);
});

test('edge failure keeps the portal suspension and exits 2 without printing secrets', async (t) => {
  const s = await setup(t, { status: 500 });
  const result = await run(s.env, 'suspend', tids[0], '--reason', 'abuse report');
  assert.equal(result.code, 2);
  assert.equal(result.json.edge, 'failed');
  assert.equal(result.json.changed, true);
  for (const secret of [s.portalKey, s.key, s.token]) assert.equal(result.stdout.includes(secret) || result.stderr.includes(secret), false);
  assert.equal((await s.useKey()).status, 401);
  assert.equal((await s.a.client.call('/api/hostnames')).status, 401);
  assert.equal(s.f.store.read('admin_audit', [])[0].edge, 'failed');
  // A missing portal key is an edge failure too; the suspension stays.
  const missing = await run({ STATE_DIRECTORY: s.f.dataDir, EDGE_INTERNAL_URL: s.internal.url }, 'suspend', tids[0], '--reason', 'abuse report');
  assert.equal(missing.code, 2);
  assert.equal(missing.json.edge, 'failed');
  assert.ok(Object.hasOwn(s.f.store.read('suspensions').tenants, tids[0]));
});

test('the CLI refuses bad arguments and unknown tenants without writing state', async (t) => {
  const s = await setup(t);
  for (const args of [[], ['suspend', tids[0]], ['suspend', tids[0], '--reason', ''], ['pause', tids[0], '--reason', 'x'],
    ['suspend', tids[0], '--reason', 'x', '--force']]) assert.equal((await run(s.env, ...args)).code, 1, JSON.stringify(args));
  assert.equal((await run(s.env, 'suspend', 'nobody@example.test', '--reason', 'x')).code, 1);
  assert.equal((await run(s.env, 'suspend', 't_zzzzzzzzzzzzzzzzzzzz', '--reason', 'x')).code, 1);
  assert.equal((await run({ ...s.env, STATE_DIRECTORY: '' }, 'suspend', tids[0], '--reason', 'x')).code, 1);
  assert.equal(s.f.store.read('suspensions', null), null);
  assert.equal(s.internal.calls.length, 0);
  assert.equal((await s.useKey()).status, 200);
});
