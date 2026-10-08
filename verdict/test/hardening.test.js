import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../src/server.js';
import { localHeuristic, resetVelocity } from '../src/engine/heuristic.js';
import { keyAuth, createKeyStore } from '../src/auth/keys.js';
import { createRateLimiter } from '../src/middleware/rateLimit.js';
import { issueClearance, validClearance, safeNext } from '../src/edge/routes.js';

async function server(fn, options = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'verdict-hardening-'));
  const app = await createApp({ keyFile: join(dir, 'keys.json'), usageFile: join(dir, 'usage.json'), ...options });
  const listener = app.listen(0, '127.0.0.1');
  await new Promise(resolve => listener.once('listening', resolve));
  try { await fn(`http://127.0.0.1:${listener.address().port}`, dir); }
  finally { await new Promise(resolve => listener.close(resolve)); await rm(dir, { recursive: true, force: true }); }
}
const post = (url, body = {}, key) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) }, body: JSON.stringify(body) });

test('structured scoring ignores arbitrary fields, field names and unstructured input', () => {
  for (const state of [{ path: '/login', ua: 'Mozilla/5.0' }, { sqlmap: true, extra: 'botnet', headers: { sqlmap: 'normal' } }, 'sqlmap', { headers: { ua: 'sqlmap' }, asn: 'sqlmap', ja3: 'headless' }]) {
    assert.equal(localHeuristic(state).action, 'allow');
  }
  assert.equal(localHeuristic({ ua: 'sqlmap' }).action, 'block');
  assert.equal(localHeuristic({ signals: ['headless'] }).action, 'challenge');
});
test('all score increments and unchanged thresholds', () => {
  for (const word of ['botnet', 'credential stuffing', 'card testing', 'sqlmap', 'nikto']) {
    for (const state of [{ ua: word }, { notes: word }, { signals: [word] }]) assert.equal(localHeuristic(state).action, 'block');
  }
  for (const word of ['headless', 'puppeteer', 'selenium', 'scrapy']) assert.equal(localHeuristic({ ua: word }).action, 'challenge');
  for (const path of ['/login', '/signin', '/oauth/callback', '/checkout']) {
    assert.ok(Math.abs(localHeuristic({ path, method: 'POST' }).confidence - 0.7) < 1e-9);
    assert.ok(Math.abs(localHeuristic({ path, signals: ['automation'] }).confidence - 0.7) < 1e-9);
  }
  assert.equal(localHeuristic({ prior_score: 1 }).action, 'challenge');
  assert.equal(localHeuristic({ account_age_hours: 0.5 }).confidence, 0.7);
  assert.equal(localHeuristic({ notes: 'headless' }).action, 'allow');
});
test('IP velocity starts on hit 31 and expires after 60 seconds', () => {
  resetVelocity();
  for (let i = 0; i < 30; i++) assert.equal(localHeuristic({ ip: '192.0.2.1', prior_score: 0.2 }, { now: 0 }).action, 'allow');
  assert.equal(localHeuristic({ ip: '192.0.2.1', prior_score: 0.2 }, { now: 1 }).action, 'challenge');
  assert.equal(localHeuristic({ ip: '192.0.2.1', prior_score: 0.2 }, { now: 60000 }).action, 'allow');
  resetVelocity();
});
test('bootstrap checks socket loopback, explicit opt-in, and existing keys', () => {
  const check = (address, hasKeys, allowBootstrap, expected) => {
    let result = 200;
    keyAuth({ hasKeys: () => hasKeys, verify: () => null }, { allowBootstrap })(
      { path: '/keys', method: 'POST', socket: { remoteAddress: address }, get: () => '127.0.0.1' },
      { status(code) { result = code; return this; }, json(body) { if (result === 403) assert.equal(body.error, 'bootstrap_disabled'); } }, () => {});
    assert.equal(result, expected);
  };
  check('203.0.113.1', false, false, 403);
  check('203.0.113.1', false, true, 200);
  for (const ip of ['127.0.0.1', '::1', '::ffff:127.0.0.1']) check(ip, false, false, 200);
  check('127.0.0.1', true, true, 401);
});
test('revoke requires auth and remains revoked after reload', () => server(async (base, dir) => {
  const { key, id } = await (await post(`${base}/v1/keys`)).json();
  assert.equal((await post(`${base}/v1/keys/${id}/revoke`)).status, 401);
  assert.equal((await post(`${base}/v1/keys/missing/revoke`, {}, key)).status, 404);
  assert.equal((await post(`${base}/v1/keys/${id}/revoke`, {}, key)).status, 200);
  assert.equal((await post(`${base}/v1/decide`, {}, key)).status, 401);
  assert.equal((await post(`${base}/v1/keys`)).status, 401);
  const store = createKeyStore(join(dir, 'keys.json')); await store.load();
  assert.equal(store.verify(key), null); assert.equal(store.hasKeys(), true);
}));
test('IP rate limit spans API keys and ignores spoofed forwarding headers', () => server(async base => {
  const { key } = await (await post(`${base}/v1/keys`)).json();
  const second = await (await post(`${base}/v1/keys`, {}, key)).json();
  assert.equal((await post(`${base}/v1/decide`, {}, key)).status, 200);
  const response = await post(`${base}/v1/decide`, {}, second.key);
  assert.equal(response.status, 429); assert.ok(response.headers.get('retry-after'));
}, { ipRateLimit: createRateLimiter({ max: 1, keyBy: req => req.socket.remoteAddress }) }));
test('decision logs contain only minimal fields and strip URL query/fragment', () => server(async (base, dir) => {
  const { key, id } = await (await post(`${base}/v1/keys`)).json();
  const response = await post(`${base}/v1/decide`, { path: '/login?token=SECRET#SECRET', notes: 'SECRET', headers: { authorization: 'SECRET' }, ua: 'Mozilla/5.0' }, key);
  assert.equal((await response.json()).action, 'allow');
  const raw = await readFile(join(dir, 'decisions.jsonl'), 'utf8');
  const row = JSON.parse(raw);
  assert.deepEqual(Object.keys(row).sort(), ['request_id', 'action', 'reason', 'engine', 'ip', 'path', 'key_id', 'ts'].sort());
  assert.equal(row.path, '/login'); assert.equal(row.key_id, id);
  assert.ok(!raw.includes('SECRET')); assert.ok(!raw.includes(key));
}));
test('clearance verifies signature, IP, wildcard and expiry', () => {
  const token = issueClearance('secret', '2001:db8::1', 300, 1000000);
  assert.equal(validClearance(token, 'secret', '2001:DB8::1', 1000000), true);
  assert.equal(validClearance(token, 'secret', '2001:db8::2', 1000000), false);
  assert.equal(validClearance(token, 'wrong', '2001:db8::1', 1000000), false);
  assert.equal(validClearance(token, 'secret', '2001:db8::1', 1300000), false);
  assert.equal(validClearance(token + 'x', 'secret', '2001:db8::1', 1000000), false);
  assert.equal(validClearance(issueClearance('secret', '*'), 'secret', '192.0.2.1'), true);
});
test('redirect destinations are local paths only', () => {
  for (const value of ['https://evil.test', '//evil.test', '/\\evil.test', '/\nevil.test', null]) assert.equal(safeNext(value), '/');
  assert.equal(safeNext('/account?tab=1'), '/account?tab=1');
});
test('challenge routes require a secret', () => server(async base => {
  assert.equal((await fetch(`${base}/challenge`)).status, 503);
  assert.equal((await post(`${base}/challenge/verify`)).status, 503);
}, { clearanceSecret: '' }));
test('edge actions, debug JSON and demo force are local; clearance bypasses challenge', () => server(async (base, dir) => {
  const headers = { 'x-forwarded-for': '192.0.2.55', 'x-forwarded-uri': '/login', 'x-forwarded-method': 'GET', 'user-agent': 'Mozilla/5.0' };
  let response = await fetch(`${base}/v1/edge-auth`, { headers });
  assert.equal(response.status, 200); assert.equal(await response.text(), '');
  response = await fetch(`${base}/v1/edge-auth`, { headers: { ...headers, 'user-agent': 'headless', accept: 'application/json' } });
  assert.equal(response.status, 401); assert.equal((await response.json()).action, 'challenge');
  assert.equal(response.headers.get('location'), '/challenge?next=%2Flogin');
  response = await fetch(`${base}/v1/edge-auth`, { headers: { ...headers, 'user-agent': 'sqlmap' } });
  assert.equal(response.status, 403);
  assert.equal((await fetch(`${base}/v1/edge-auth`, { headers: { ...headers, 'x-verdict-force': 'block' } })).status, 200);
  const page = await fetch(`${base}/challenge?next=https://evil.test`); assert.equal(page.status, 200);
  assert.ok((await page.text()).includes("fetch('/challenge/verify'"));
  response = await fetch(`${base}/challenge/verify`, { method: 'POST', headers });
  assert.deepEqual(await response.json(), { ok: true });
  const cookie = response.headers.get('set-cookie');
  for (const flag of ['HttpOnly', 'Secure', 'SameSite=Lax', 'Max-Age=300']) assert.ok(cookie.includes(flag));
  assert.equal((await fetch(`${base}/v1/edge-auth`, { headers: { ...headers, 'user-agent': 'headless', cookie: cookie.split(';')[0] } })).status, 200);
  assert.equal((await fetch(`${base}/v1/edge-auth`, { headers: { ...headers, 'x-forwarded-for': '192.0.2.56', 'user-agent': 'headless', cookie: cookie.split(';')[0] } })).status, 401);
  const logs = (await readFile(join(dir, 'decisions.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.ok(logs.every(row => row.key_id === null));
}, { clearanceSecret: 'fixed-test-secret' }));
test('demo force is explicitly opt-in', () => server(async base => {
  for (const [action, status] of [['allow', 200], ['challenge', 401], ['block', 403]]) {
    const response = await fetch(`${base}/v1/edge-auth`, { headers: { 'x-verdict-force': action, accept: 'application/json' } });
    assert.equal(response.status, status); assert.equal((await response.json()).reason, 'demo_force');
  }
}, { demoForce: true }));
test('wrapped state validates fields and scores the actual object', () => server(async base => {
  const { key } = await (await post(`${base}/v1/keys`)).json();
  assert.equal((await post(`${base}/v1/decide`, { state: { signals: 123 } }, key)).status, 400);
  const response = await post(`${base}/v1/decide`, { state: { ua: 'sqlmap' } }, key);
  assert.equal((await response.json()).action, 'block');
}));

test('rate limiter window expires independently of key identity', () => {
  const limiter = createRateLimiter({ max: 1, windowMs: 100, keyBy: req => req.ip });
  const originalNow = Date.now;
  let now = 0; Date.now = () => now;
  try {
    const statuses = [];
    const run = () => limiter({ ip: '192.0.2.1' }, { setHeader() {}, status(code) { statuses.push(code); return this; }, json() {} }, () => statuses.push(200));
    run(); run(); now = 100; run();
    assert.deepEqual(statuses, [200, 429, 200]);
  } finally { Date.now = originalNow; }
});

test('challenge browser script verifies then safely redirects', () => server(async base => {
  const { runInNewContext } = await import('node:vm');
  const html = await (await fetch(`${base}/challenge`)).text();
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  for (const [destination, expected] of [['/account?x=1', '/account?x=1'], ['//evil.test', '/'], ['/\\evil.test', '/'], ['https://evil.test', '/']]) {
    let redirected;
    let verified = false;
    await runInNewContext(script, { URLSearchParams, location: { search: `?next=${encodeURIComponent(destination)}`, replace(value) { assert.equal(verified, true); redirected = value; } }, fetch: async (path, options) => { assert.equal(path, '/challenge/verify'); assert.equal(options.method, 'POST'); verified = true; return { ok: true }; }, document: { getElementById: () => ({}) } });
    assert.equal(redirected, expected);
  }
}, { clearanceSecret: 'test-secret' }));

test('server defaults to loopback and accepts explicit VERDICT_BIND', async () => {
  const { spawn } = await import('node:child_process');
  const dir = await mkdtemp(join(tmpdir(), 'verdict-bind-'));
  try {
    for (const bind of [undefined, '127.0.0.2']) {
      const env = { ...process.env, PORT: '0', VERDICT_KEY_FILE: join(dir, 'keys.json'), VERDICT_USAGE_FILE: join(dir, 'usage.json') };
      delete env.VERDICT_BIND; delete env.TYPESAFE_API_KEY;
      if (bind) env.VERDICT_BIND = bind;
      const child = spawn(process.execPath, ['src/server.js'], { env, stdio: ['ignore', 'pipe', 'pipe'] });
      const exited = new Promise(resolve => child.once('exit', resolve));
      try {
        const output = await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('server startup timeout')), 5000);
          child.once('error', error => { clearTimeout(timer); reject(error); });
          child.stdout.once('data', data => { clearTimeout(timer); resolve(data.toString()); });
          child.once('exit', code => { clearTimeout(timer); reject(new Error(`server exited: ${code}`)); });
        });
        assert.ok(output.includes(`listening on ${bind || '127.0.0.1'}:`));
      } finally { child.kill(); await exited; }
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
