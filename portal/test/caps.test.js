import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { EventEmitter } from 'node:events';
import { createSessions, DAY } from '../src/sessions.js';
import { createRateLimits } from '../src/rate-limits.js';
import { createApp } from '../src/app.js';
import { createStore } from '../src/store.js';
import { hashPassword } from '../src/passwords.js';
import { digest } from '../src/tokens.js';
import { temporary, origin, tids } from './helpers.js';

function memoryStore(initial = {}) {
  const data = structuredClone(initial);
  let writes = 0;
  return { read: (name, fallback) => structuredClone(data[name] ?? fallback),
    write(name, value) { writes++; data[name] = structuredClone(value); },
    get writes() { return writes; } };
}
const row = (i, time, user_id = null) => ({ token_hash: digest(`synthetic-${i}`), csrf: 'synthetic', user_id,
  auth_version: 1, created_at: time - 1000, last_seen: time, expires_at: time + (user_id === null ? 1800000 : 14 * DAY) });

// Exercise the HTTP handler without opening sockets or making network calls.
function call(app, path, session, body) {
  return new Promise((resolve) => {
    const req = Readable.from(body ? [Buffer.from(JSON.stringify(body))] : []);
    Object.assign(req, { url: path, method: body ? 'POST' : 'GET', socket: { remoteAddress: '127.0.0.1' },
      headers: { origin, cookie: session?.cookie, 'x-fd-csrf': session?.csrf, 'content-type': 'application/json' } });
    const res = new EventEmitter();
    const headers = {};
    res.setHeader = (key, value) => { headers[key.toLowerCase()] = value; };
    res.writeHead = (status, values) => { res.statusCode = status; res.headersSent = true; Object.entries(values).forEach(([key, value]) => res.setHeader(key, value)); };
    res.end = (text) => { res.emit('finish'); resolve({ status: res.statusCode, data: JSON.parse(text), headers }); };
    app.emit('request', req, res);
  });
}
async function setup(t) {
  const dataDir = temporary(t);
  const store = createStore(dataDir);
  let time = Date.parse('2026-01-01T00:00:00Z');
  const now = () => time;
  const user = { id: 'synthetic-user', email: 'user@example.test', tenant_id: tids[0], auth_version: 1,
    email_verified_at: new Date(time).toISOString(), password_hash: await hashPassword('synthetic-password-123') };
  store.write('accounts', { users: [user], tenants: [{ id: tids[0], status: 'active' }], invites: [], links: [] });
  const app = createApp({ dataDir, now, config: { origin }, edge: { async rotateCredential() { return { credential: {} }; } } });
  return { store, now, user, app, sessions: createSessions(store, now), advance: (ms) => { time += ms; } };
}
const credentials = { email: 'user@example.test', password: 'synthetic-password-123' };

test('anonymous cap evicts oldest anonymous session and login still works', async (t) => {
  const f = await setup(t);
  const live = f.sessions.create(f.user);
  const rows = Array.from({ length: 5000 }, (_, i) => row(i, f.now()));
  rows[123].created_at -= 1000;
  f.store.write('sessions', [...rows, ...f.store.read('sessions')]);
  const bootstrap = await call(f.app, '/api/me');
  assert.equal(bootstrap.status, 200);
  const saved = f.store.read('sessions');
  assert.equal(saved.filter((s) => s.user_id === null).length, 5000);
  assert.ok(!saved.some((s) => s.token_hash === rows[123].token_hash));
  assert.ok(f.sessions.get(live.cookie));
  const login = await call(f.app, '/api/login', { cookie: bootstrap.headers['set-cookie'], csrf: bootstrap.data.csrf }, credentials);
  assert.equal(login.status, 200);
  assert.match(login.headers['set-cookie'], /Max-Age=1209600/);
});

test('authenticated cap returns 429, preserves bootstrap, then admits login after expiry', async (t) => {
  const f = await setup(t);
  f.store.write('sessions', Array.from({ length: 20000 }, (_, i) => row(i, f.now(), 'synthetic-user')));
  const session = f.sessions.create();
  const result = await call(f.app, '/api/login', session, credentials);
  assert.equal(result.status, 429);
  assert.equal(result.data.error, 'rate_limited');
  assert.ok(Number(result.headers['retry-after']) > 0);
  assert.ok(f.sessions.get(session.cookie));
  const rows = f.store.read('sessions');
  rows[0].expires_at = f.now();
  f.store.write('sessions', rows);
  assert.equal((await call(f.app, '/api/login', session, credentials)).status, 200);
  assert.equal(f.store.read('sessions').length, 20000);
});

test('full login-account prefix allows a new real login and rotate, but rejects invalid credentials', async (t) => {
  const f = await setup(t);
  const session = f.sessions.create(f.user);
  const entries = Object.fromEntries(Array.from({ length: 20000 }, (_, i) => [`login-account:${digest(`junk${i}@example.test`)}`, { count: 1, reset: f.now() + 900000 }]));
  f.store.write('rate_limits', entries);
  assert.equal((await call(f.app, '/api/hostnames/app.example.test/rotate', session, {})).status, 200);
  assert.equal((await call(f.app, '/api/login', session, { ...credentials, password: 'synthetic-wrong-password' })).status, 429);
  assert.equal((await call(f.app, '/api/login', session, credentials)).status, 200);
  const limits = createRateLimits(f.now, f.store);
  assert.throws(() => limits.take('login-account:new', 5, 900000, true), { code: 'rate_limited' });
  limits.take('rotate:synthetic', 5, DAY, true);
  const existing = `login-account:${digest('junk0@example.test')}`;
  for (let i = 0; i < 4; i++) limits.take(existing, 5, 900000, true);
  assert.throws(() => createRateLimits(f.now, f.store).take(existing, 5, 900000, true), { code: 'rate_limited' });
  f.advance(900000);
  limits.take('login-account:new', 5, 900000, true);
  assert.equal(Object.keys(f.store.read('rate_limits')).length, 3);
});

test('in-memory prefixes have independent caps and reclaim expired entries', () => {
  let time = 0;
  const limits = createRateLimits(() => time, memoryStore());
  for (let i = 0; i < 20000; i++) limits.take(`signup:${i}`, 3, 1000);
  assert.throws(() => limits.take('signup:new', 3, 1000), { code: 'rate_limited' });
  limits.take('signup:0', 3, 1000);
  limits.take('signup:0', 3, 1000);
  assert.throws(() => limits.take('signup:0', 3, 1000), { code: 'rate_limited' });
  limits.take('rotate:synthetic', 5, DAY);
  time = 1000;
  limits.take('signup:new', 3, 1000);
});

test('last_seen writes are throttled to 60 seconds and anonymous idle TTL is 30 minutes', () => {
  let time = 0;
  const store = memoryStore();
  const sessions = createSessions(store, () => time);
  const anon = sessions.create();
  const auth = sessions.create({ id: 'synthetic-user', auth_version: 1 });
  assert.match(anon.cookie, /Max-Age=1800/);
  for (const session of [anon, auth]) {
    const before = store.writes;
    time = 59999;
    assert.equal(sessions.get(session.cookie).last_seen, 0);
    assert.equal(store.writes, before);
    time = 60000;
    assert.equal(sessions.get(session.cookie).last_seen, 60000);
    assert.equal(store.writes, before + 1);
    sessions.get(session.cookie);
    assert.equal(store.writes, before + 1);
  }
  time += 1800000;
  assert.equal(sessions.get(anon.cookie), null);
  assert.ok(sessions.get(auth.cookie));
});
