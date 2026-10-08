import { promisify } from 'node:util';
import { localHeuristic, resetVelocity } from '../src/engine/heuristic.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { execFile, execFileSync } from 'node:child_process';
import { createApp } from '../src/server.js';
import { createKeyStore, keyAuth } from '../src/auth/keys.js';
import { ENFORCE_DENYLIST, validateHostConfig, createHostStore } from '../src/config/hosts.js';
import { readConfig, writeConfig } from '../src/config/files.js';
import { binding, clientIP, hasWork, issueClearance, validClearance, unseal, DEMO_HOST } from '../src/edge/security.js';
import { createRateLimiter } from '../src/middleware/rateLimit.js';
const secret = 'advsec-fixture-only';
async function temporary(fn) {
  const dir = await mkdtemp(join(process.cwd(), '.advsec-'));
  try { await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}
async function serve(fn) {
  return temporary(async dir => {
    const keys = createKeyStore(join(dir, 'keys.json')); await keys.load();
    const admin = await keys.create('fixture'), panel = await keys.create('panel', { scope: 'read' });
    const app = await createApp({ keyFile: join(dir, 'keys.json'), usageFile: join(dir, 'usage.json'), clearanceSecret: secret, demoForce: true });
    const server = app.listen(0, '127.0.0.1'); await new Promise(r => server.once('listening', r));
    const request = (path, { headers = {}, body, method = 'GET' } = {}) => fetch(`http://127.0.0.1:${server.address().port}${path}`, {
      method, headers: { 'x-forwarded-host': 'shop.example', 'x-forwarded-for': '192.0.2.15', 'user-agent': 'sqlmap', 'content-type': 'application/json', ...headers },
      ...(body === undefined ? {} : { body: typeof body === 'string' ? body : JSON.stringify(body) }),
    });
    try { await fn({ request, admin, panel, app, dir, base: `http://127.0.0.1:${server.address().port}` }); }
    finally { server.closeAllConnections(); await new Promise(r => server.close(r)); await app.locals.flush(); }
  });
}
const req = (headers, peer = '203.0.113.4') => ({ socket: { remoteAddress: peer }, get: name => headers[name] });
test('advsec auth: rotation, revoked keys, hashed storage and empty config', () => temporary(async dir => {
  const file = join(dir, 'keys.json'), store = createKeyStore(file); await store.load();
  for (const key of ['', undefined, 'fixture']) assert.equal(store.verify(key), null);
  const a = await store.create('a'), b = await store.create('b', { scope: 'read' });
  assert.ok(store.verify(a.key)); assert.equal(store.verify(b.key).scope, 'read');
  const disk = await readFile(file, 'utf8'); assert.ok(!disk.includes(a.key) && !disk.includes(b.key));
  assert.ok(!JSON.stringify(store.list()).includes('hash'));
  await store.revoke(a.id); await store.load(); assert.equal(store.verify(a.key), null); assert.ok(store.verify(b.key));
}));
test('advsec auth: proxy and cross-origin bootstrap fail closed', () => {
  for (const headers of [{ 'x-forwarded-for': '192.0.2.1' }, { origin: 'https://attacker.example' }]) {
    let status;
    keyAuth({ hasKeys: () => false }, { allowBootstrap: false })({ ...req(headers, '127.0.0.1'), method: 'POST', path: '/keys' }, { status(n) { status = n; return this; }, json() {} }, () => assert.fail('bootstrap bypass'));
    assert.equal(status, 403);
  }
});
test('advsec forwarding: remote peer cannot select tenant/IP; local proxy uses rightmost hop', () => {
  const h = { host: 'shop.example', 'x-forwarded-host': DEMO_HOST, 'x-forwarded-for': '1.2.3.4, 192.0.2.9', 'x-real-ip': '1.2.3.4', forwarded: 'for=1.2.3.4;host=evil.example' };
  assert.equal(binding(req(h)).host, 'shop.example'); assert.equal(clientIP(req(h)), '203.0.113.4');
  assert.equal(binding(req(h, '127.0.0.1')).host, DEMO_HOST); assert.equal(clientIP(req(h, '127.0.0.1')), '192.0.2.9');
  assert.equal(clientIP(req(h, '')), '0.0.0.0');
});
test('advsec demo: production force variants cannot bypass block or mint clearance', () => serve(async ({ request }) => {
  for (const path of ['/v1/edge-auth?force=allow&demo=1', '/v1/edge-auth?verdict=allow']) {
    const r = await request(path, { headers: { 'x-verdict-demo': '1', 'x-verdict-force': 'allow', 'x-forwarded-uri': '/?verdict=allow&force=allow', accept: 'application/json' } });
    assert.equal(r.status, 403); assert.notEqual((await r.json()).reason, 'demo_force'); assert.equal(r.headers.get('set-cookie'), null);
  }
  assert.equal((await request('/v1/edge-auth', { method: 'POST', body: { force: 'allow', demo: true } })).status, 401);
  assert.equal((await request('/v1/edge-auth', { headers: { 'x-forwarded-host': DEMO_HOST, 'x-verdict-demo': '1', 'x-verdict-force': 'allow' } })).status, 200);
  const spoof = await request('/v1/edge-auth', { headers: { 'user-agent': 'Googlebot/2.1', 'sec-ch-ua': '"Chromium";v="130"' } });
  assert.notEqual(spoof.status, 200); assert.equal(spoof.headers.get('set-cookie'), null);
}));
test('advsec guardrails: authority variants and injection cannot enable enforce', () => {
  for (const host of ENFORCE_DENYLIST) for (const variant of [host, host.toUpperCase(), `${host}.`, `${host}:443`, `${host}.:443`, `${host}..`, ` ${host}`, `${host}\0`, host.replace('.', '%2e'), host.replace('.', '\u3002')]) assert.throws(() => validateHostConfig({ mode: 'enforce', enable: true }, { host: variant }));
  for (const host of ['../escape', 'x;touch-pwned', 'x\nimport evil', '-bad.example', 'xn--', 'a..example']) assert.throws(() => validateHostConfig({ mode: 'enforce' }, { host }));
  assert.equal(validateHostConfig({ mode: 'enforce' }, { host: 'xn--bcher-kva.example' }).host, 'xn--bcher-kva.example');
});
test('advsec guardrails: runtime denylist and shadow/off override scoring and force', () => serve(async ({ request, app }) => {
  for (const host of ENFORCE_DENYLIST) for (const variant of [host.toUpperCase(), `${host}.:443`]) {
    const r = await request('/v1/edge-auth', { headers: { 'x-forwarded-host': variant, 'x-verdict-demo': '1', 'x-verdict-force': 'block' } });
    assert.equal(r.status, 200); assert.equal(r.headers.get('x-verdict-action'), 'allow');
  }
  for (const mode of ['shadow', 'off']) { await app.locals.hostStore.set('shop.example', { enable: true, mode }); assert.equal((await request('/v1/edge-auth')).status, 200); }
  assert.equal((await request('/v1/edge-auth', { headers: { 'x-forwarded-host': 'shop.example,evil.example' } })).status, 400);
}));
test('advsec clearance: forgery, algorithm confusion, context/expiry replay and invalid difficulty', () => {
  const bound = { host: 'shop.example', ip: '192.0.2.1', ua: 'fixture' }, now = 1000000;
  const cookie = issueClearance(secret, bound, 300, now), [payload, mac] = cookie.split('.');
  for (const forged of [`${payload}.${mac.slice(0, -1)}`, `${payload}.none`, `${payload}.${mac}.extra`, issueClearance('wrong', bound, 300, now)]) assert.equal(validClearance(forged, secret, bound, now), false);
  for (const context of [{ ...bound, host: 'other.example' }, { ...bound, ip: '192.0.3.1' }, { ...bound, ua: 'other' }]) assert.equal(validClearance(cookie, secret, context, now), false);
  assert.ok(validClearance(cookie, secret, { ...bound, ip: '192.0.2.254' }, now)); assert.equal(validClearance(cookie, secret, bound, now + 300000), false);
  const v6 = { ...bound, ip: '2001:db8:1:2::1' }, token = issueClearance(secret, v6, 300, now);
  assert.ok(validClearance(token, secret, { ...v6, ip: '2001:db8:1:2::ffff' }, now)); assert.equal(validClearance(token, secret, { ...v6, ip: '2001:db8:1:3::1' }, now), false);
  for (const bits of [-1, 0, NaN, Infinity, 257, '16']) assert.equal(hasWork('id', '0', bits), false);
  assert.equal(unseal('payload.mac', ''), null);
});
test('advsec PoW: precomputed, cross-host/prefix and consumed proofs fail; production fallback denied', () => serve(async ({ request }) => {
  const issue = await (await request('/challenge/issue?difficulty=-1&score=NaN&force=allow')).json(); assert.equal(issue.difficulty, 16);
  let nonce = 0; while (!hasWork(issue.challenge_id, String(nonce), issue.difficulty)) nonce++;
  const body = { challenge_id: issue.challenge_id, nonce: String(nonce) };
  for (const headers of [{ 'x-forwarded-host': 'other.example' }, { 'x-forwarded-for': '192.0.3.1' }]) assert.equal((await request('/challenge/verify', { method: 'POST', body, headers })).status, 400);
  assert.equal((await request('/challenge/verify', { method: 'POST', body: { ...body, challenge_id: 'precomputed-id' } })).status, 400);
  const success = await request('/challenge/verify', { method: 'POST', body }); assert.equal(success.status, 200); assert.ok(success.headers.get('set-cookie'));
  assert.equal((await request('/challenge/verify', { method: 'POST', body })).status, 400);
  const fallback = await request('/challenge/verify-fallback', { method: 'POST', body: { confirm: 'yes', answer: '42' } }); assert.equal(fallback.status, 403); assert.equal(fallback.headers.get('set-cookie'), null);
  assert.ok(!(await (await request('/challenge')).text()).includes('name="token"'));
}));
test('advsec panel: operational data needs bearer; cookie auth and read-key mutations fail', () => serve(async ({ request, panel }) => {
  for (const path of ['/metrics', '/v1/hosts', '/v1/usage', '/v1/ops/metrics', '/v1/ops/recent-decisions', '/v1/ops/shadow-summary']) {
    assert.equal((await request(path)).status, 401); assert.equal((await request(path, { headers: { cookie: `panel_key=${panel.key}` } })).status, 401);
  }
  assert.equal((await request('/metrics', { headers: { authorization: `Bearer ${panel.key}` } })).status, 200);
  for (const path of ['/v1/keys', '/v1/decide']) assert.equal((await request(path, { method: 'POST', headers: { authorization: `Bearer ${panel.key}` }, body: {} })).status, 403);
}));
test('advsec config: bounded JSON, symlink reads, atomic writes and generator injection', () => temporary(async dir => {
  const file = join(dir, 'hosts.json'), target = join(dir, 'target'); await writeFile(target, 'unchanged'); await symlink(target, file);
  await assert.rejects(readConfig(file)); await writeConfig(file, '{}'); assert.equal(await readFile(target, 'utf8'), 'unchanged');
  for (const value of ['{invalid', ' '.repeat(1024 * 1024 + 1), '[]']) { await writeFile(file, value); await assert.rejects(createHostStore(file).load()); }
  const out = join(dir, 'out;$(touch INJECTED)'), env = { PATH: process.env.PATH, VERDICT_HOSTS_FILE: file, VERDICT_CADDY_SNIPPET_DIR: out };
  await writeFile(file, JSON.stringify({ hosts: { 'safe.example': { enable: true, mode: 'enforce' } } }));
  execFileSync(process.execPath, ['scripts/caddy-apply-hosts.js'], { env, stdio: 'pipe' }); assert.match(await readFile(join(out, 'verdict-hosts.caddy'), 'utf8'), /X-Forwarded-For \{remote_host\}/);
  assert.throws(() => execFileSync(process.execPath, ['scripts/caddy-apply-hosts.js', '--apply'], { env, stdio: 'pipe' }), /Automatic apply disabled/);
}));
test('advsec DoS: oversized headers/body and deep JSON rejected early', () => serve(async ({ request, admin }) => {
  const headers = { authorization: `Bearer ${admin.key}` };
  assert.equal((await request('/v1/decide', { method: 'POST', headers, body: { notes: 'x'.repeat(270000) } })).status, 413);
  assert.equal((await request('/v1/decide', { method: 'POST', headers, body: '{"x":'.repeat(40) + '0' + '}'.repeat(40) })).status, 400);
  assert.equal((await request('/v1/edge-auth', { headers: { 'x-oversized': 'x'.repeat(9000) } })).status, 431);
  assert.equal((await request('/v1/decide', { method: 'POST', headers, body: { path: '/' + 'a'.repeat(2048) } })).status, 400);
}));
test('advsec DoS: capacity rejects new identities without resetting existing limits', () => {
  const limiter = createRateLimiter({ capacity: 2, max: 1, keyBy: r => r.id });
  const statuses = [], res = { setHeader() {}, status(n) { statuses.push(n); return this; }, json() {} };
  for (const id of ['a', 'b', 'c', 'a']) limiter({ id }, res, () => statuses.push(200));
  assert.deepEqual(statuses, [200, 200, 429, 429]);
});

test('advsec CLI: enforce denylist and path traversal attacks fail at API boundary', () => serve(async ({ base, admin, app }) => {
  const env = { PATH: process.env.PATH, VERDICT_URL: base, VERDICT_API_KEY: admin.key };
  for (const host of ['FASTDOGNETWORKS.COM.:443', '../escape', 'x;touch-injected']) {
    await assert.rejects(promisify(execFile)(process.execPath, ['scripts/verdict-hosts.js', 'set', host, 'enable=1', 'mode=enforce'], { env }));
  }
  assert.deepEqual(app.locals.hostStore.list(), []);
}));
test('advsec velocity: attacker-selected identities cannot grow beyond fixed capacity', () => {
  resetVelocity();
  for (let i = 0; i < 10000; i++) localHeuristic({ ip: `fixture-${i}` }, { now: 0 });
  assert.ok(localHeuristic({ ip: 'overflow' }, { now: 0 }).reasons.includes('ip_velocity'));
  assert.ok(!localHeuristic({ ip: 'after-expiry' }, { now: 60000 }).reasons.includes('ip_velocity'));
  resetVelocity();
});
test('advsec config: invalid key records fail startup and generated-file symlinks cannot overwrite targets', () => temporary(async dir => {
  const file = join(dir, 'keys.json');
  for (const value of ['{}', '[null]', '[{"id":"fixture","hash":"bad"}]']) {
    await writeFile(file, value); await assert.rejects(createKeyStore(file).load());
  }
  const target = join(dir, 'target'), output = join(dir, 'verdict-hosts.caddy'), hosts = join(dir, 'hosts.json');
  await writeFile(target, 'unchanged'); await symlink(target, output); await writeFile(hosts, '{}');
  execFileSync(process.execPath, ['scripts/caddy-apply-hosts.js'], { env: { PATH: process.env.PATH, VERDICT_HOSTS_FILE: hosts, VERDICT_CADDY_SNIPPET_DIR: dir }, stdio: 'pipe' });
  assert.equal(await readFile(target, 'utf8'), 'unchanged');
}));
