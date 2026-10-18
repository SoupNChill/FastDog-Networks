import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { hashPassword, validPassword, verifyPassword } from '../src/passwords.js';
import { createInvites, findInvite } from '../src/invites.js';
import { createFileMailer } from '../src/mailer-file.js';
import { fixture, browser, fakeSecret, linkToken, temporary, origin, request } from './helpers.js';

test('scrypt parameters, unique salts, password policy and comparisons', async () => {
  const password = fakeSecret();
  const hash = await hashPassword(password);
  assert.equal(hash.N, 32768);
  assert.equal(hash.r, 8);
  assert.equal(hash.p, 1);
  assert.equal(hash.salt.length, 32);
  assert.notEqual(hash.salt, (await hashPassword(password)).salt);
  assert.ok(await verifyPassword(password, hash));
  assert.equal(await verifyPassword(fakeSecret(), hash), false);
  assert.equal(validPassword('short'), false);
  assert.equal(validPassword('PASSWORD1234'), false);
  assert.equal(validPassword('x'.repeat(1025)), false);
  assert.equal(await verifyPassword(password, { ...hash, N: 1 }), false);
});

test('anonymous CSRF bootstrap, cookie attributes, login renewal and logout', async (t) => {
  const f = await fixture(t);
  const bootstrap = await f.client.call('/api/me');
  assert.equal(bootstrap.data.email, null);
  const attributes = bootstrap.headers['set-cookie'][0];
  for (const attribute of ['__Host-fd_session=', 'Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=1800']) assert.ok(attributes.includes(attribute));
  assert.ok(!attributes.includes('Domain='));
  const { client, user, password } = await f.seed();
  const beforeLogin = client.cookie;
  assert.equal((await client.call('/api/login', 'POST', { email: user.email, password })).status, 200);
  assert.notEqual(client.cookie, beforeLogin);
  assert.equal((await request(f.port, '/api/hostnames', { headers: { cookie: beforeLogin } })).status, 401);
  await client.call('/api/me');
  const initial = client.cookie;
  const raw = initial.split('=')[1];
  assert.ok(!readFileSync(join(f.dataDir, 'sessions.json'), 'utf8').includes(raw));
  f.advance(13 * 86400000);
  assert.ok((await client.call('/api/me')).data.tenant);
  f.advance(13 * 86400000);
  assert.ok((await client.call('/api/me')).data.tenant);
  assert.equal(client.cookie, initial);
  const logout = await client.call('/api/logout', 'POST');
  assert.equal((await request(f.port, '/api/hostnames', { headers: { cookie: initial } })).status, 401);
  assert.match(logout.headers['set-cookie'][0], /Max-Age=0/);
  assert.equal((await client.call('/api/hostnames')).status, 401);
});

test('sessions have a 14-day idle expiry and 90-day absolute expiry', async (t) => {
  const f = await fixture(t);
  const a = await f.seed();
  f.advance(14 * 86400000);
  assert.equal((await a.client.call('/api/hostnames')).status, 401);
  const b = await f.seed(1);
  for (let i = 0; i < 8; i++) {
    f.advance(10 * 86400000);
    assert.equal((await b.client.call('/api/hostnames')).status, 200);
  }
  f.advance(9 * 86400000);
  const nearExpiry = await b.client.call('/api/me');
  assert.match(nearExpiry.headers['set-cookie'][0], /Max-Age=86400(?:;|$)/);
  f.advance(86400000);
  assert.equal((await b.client.call('/api/hostnames')).status, 401);
});

test('every write checks exact Origin and per-session CSRF, including login and signup', async (t) => {
  const f = await fixture(t);
  for (const path of ['/api/signup', '/api/login', '/api/logout', '/api/verify-email', '/api/password-reset', '/api/password-reset/confirm', '/api/hostnames', '/api/domain-requests']) {
    for (const headers of [{ origin: '' }, { origin: 'https://other.example.com' }, { 'x-fd-csrf': '' }, { 'x-fd-csrf': fakeSecret() }]) {
      assert.equal((await f.client.call(path, 'POST', {}, headers)).status, 401, path);
    }
  }
  const other = browser(f.port);
  await other.call('/api/me');
  assert.equal((await f.client.call('/api/logout', 'POST', {}, { 'x-fd-csrf': other.csrf })).status, 401);
});

test('invite signup is email-bound, generic, single use, and verifies one-time hashed links', async (t) => {
  const f = await fixture(t);
  const invites = createInvites({ dataDir: f.dataDir, now: f.now });
  const code = invites.mint({ email: 'new@example.com', plan: 'plan-from-invite', hostnameLimit: 9 });
  const password = fakeSecret();
  assert.ok(!readFileSync(join(f.dataDir, 'accounts.json'), 'utf8').includes(code));
  const wrong = await f.client.call('/api/signup', 'POST', { email: 'other@example.com', password, invite_code: code, accept_terms: true });
  assert.equal(f.messages.length, 0);
  const good = await f.client.call('/api/signup', 'POST', { email: 'NEW@example.com', password, invite_code: code, accept_terms: true });
  assert.deepEqual(good.data, wrong.data);
  assert.equal(f.messages.length, 1);
  const repeated = await f.client.call('/api/signup', 'POST', { email: 'new@example.com', password, invite_code: code, accept_terms: true });
  assert.equal(repeated.status, good.status);
  assert.deepEqual(repeated.data, good.data);
  assert.equal(f.messages.length, 1);
  const saved = f.store.read('accounts');
  assert.match(saved.tenants[0].id, /^t_[a-z2-7]{20}$/);
  assert.equal(saved.tenants[0].plan, 'plan-from-invite');
  assert.equal(saved.tenants[0].hostname_limit, 9);
  assert.equal(saved.invites[0].tenant_id, saved.tenants[0].id);
  assert.equal(findInvite(saved, code, saved.users[0].email, f.now()), undefined);
  assert.equal(saved.users.length, 1);
  assert.equal(saved.tenants.length, 1);
  assert.equal((await f.client.call('/api/login', 'POST', { email: 'new@example.com', password })).status, 200);
  await f.client.call('/api/me');
  assert.equal((await f.client.call('/api/hostnames', 'POST', { hostname: 'app.example.com' })).status, 401);
  const token = linkToken(f.messages[0]);
  assert.equal(new URL(f.messages[0].link).search, '');
  assert.ok(!readFileSync(join(f.dataDir, 'accounts.json'), 'utf8').includes(token));
  assert.equal((await f.client.call('/api/verify-email', 'POST', { token })).status, 200);
  assert.equal((await f.client.call('/api/verify-email', 'POST', { token })).status, 401);
  assert.equal((await f.client.call('/api/hostnames', 'POST', { hostname: 'app.example.com' })).status, 201);
});

test('expired and wrong invite codes have the same generic response and no account', async (t) => {
  const f = await fixture(t);
  const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email: 'new@example.com', expiresAt: f.now() + 1000 });
  f.advance(1000);
  const body = { email: 'new@example.com', password: fakeSecret() };
  const a = await f.client.call('/api/signup', 'POST', { ...body, invite_code: code, accept_terms: true });
  const b = await f.client.call('/api/signup', 'POST', { ...body, invite_code: fakeSecret(), accept_terms: true });
  assert.deepEqual(a.data, b.data);
  assert.equal(f.messages.length, 0);
  assert.equal(f.store.read('accounts').users.length, 0);
});

test('reset links expire, are single-use, revoke all sessions, and reject old password', async (t) => {
  const f = await fixture(t);
  const { client, user, password } = await f.seed();
  const second = browser(f.port);
  await second.call('/api/me');
  await second.call('/api/login', 'POST', { email: user.email, password });
  const unknown = await f.client.call('/api/password-reset', 'POST', { email: 'absent@example.com' });
  const known = await f.client.call('/api/password-reset', 'POST', { email: user.email });
  assert.deepEqual(known.data, unknown.data);
  const expired = linkToken(f.messages[0]);
  assert.ok(!readFileSync(join(f.dataDir, 'accounts.json'), 'utf8').includes(expired));
  f.advance(3600000);
  const nextPassword = fakeSecret();
  await f.client.call('/api/me');
  assert.equal((await f.client.call('/api/password-reset/confirm', 'POST', { token: expired, password: nextPassword })).status, 401);
  await f.client.call('/api/password-reset', 'POST', { email: user.email });
  const token = linkToken(f.messages[1]);
  assert.equal((await f.client.call('/api/password-reset/confirm', 'POST', { token, password: nextPassword })).status, 200);
  assert.equal((await client.call('/api/hostnames')).status, 401);
  assert.equal((await second.call('/api/hostnames')).status, 401);
  await f.client.call('/api/me');
  assert.equal((await f.client.call('/api/password-reset/confirm', 'POST', { token, password: nextPassword })).status, 401);
  assert.equal((await f.client.call('/api/login', 'POST', { email: user.email, password })).status, 401);
  assert.equal((await f.client.call('/api/login', 'POST', { email: user.email, password: nextPassword })).status, 200);
});

test('verification links expire at one hour', async (t) => {
  const f = await fixture(t);
  const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email: 'new@example.com' });
  await f.client.call('/api/signup', 'POST', { email: 'new@example.com', password: fakeSecret(), invite_code: code, accept_terms: true });
  f.advance(3600000);
  await f.client.call('/api/me');
  assert.equal((await f.client.call('/api/verify-email', 'POST', { token: linkToken(f.messages[0]) })).status, 401);
});

test('file mailer stores private messages in mode 0600 without exposing them via API', async (t) => {
  const outboxDir = temporary(t);
  const link = `${origin}/login#token=${fakeSecret()}`;
  await createFileMailer({ outboxDir }).send({ to: 'user@example.com', kind: 'verify-email', link });
  const file = join(outboxDir, readdirSync(outboxDir)[0]);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(JSON.parse(readFileSync(file)).link, link);
});

test('concurrent signup and reset requests consume each one-time capability once', async (t) => {
  const f = await fixture(t);
  const email = 'new@example.com';
  const password = fakeSecret();
  const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email });
  const responses = await Promise.all([1, 2].map(() => f.client.call('/api/signup', 'POST', { email, password, invite_code: code, accept_terms: true })));
  assert.ok(responses.every((response) => response.status === 200));
  assert.equal(f.store.read('accounts').users.length, 1);
  assert.equal(f.store.read('accounts').tenants.length, 1);
  assert.equal(f.messages.length, 1);
  await f.client.call('/api/password-reset', 'POST', { email });
  const token = linkToken(f.messages.at(-1));
  const next = fakeSecret();
  const resets = await Promise.all([1, 2].map(() => f.client.call('/api/password-reset/confirm', 'POST', { token, password: next })));
  assert.deepEqual(resets.map((response) => response.status).sort(), [200, 401]);
});

test('existing email with a fresh invite receives the generic signup response', async (t) => {
  const f = await fixture(t);
  const { user } = await f.seed();
  const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email: user.email });
  const before = f.store.read('accounts');
  const existing = await f.client.call('/api/signup', 'POST', { email: user.email, password: fakeSecret(), invite_code: code, accept_terms: true });
  const unknown = await f.client.call('/api/signup', 'POST', { email: 'absent@example.test', password: fakeSecret(), invite_code: fakeSecret(), accept_terms: true });
  assert.equal(existing.status, 200);
  assert.equal(existing.status, unknown.status);
  assert.deepEqual(existing.data, unknown.data);
  assert.deepEqual(f.store.read('accounts'), before);
  assert.equal(f.messages.length, 0);
});

for (const trustedSource of [true, false]) {
  test(`TRUST_PROXY IP limit with ${trustedSource ? 'loopback' : 'untrusted'} source and X-Forwarded-For`, async (t) => {
    const f = await fixture(t, { trustProxy: true });
    // Simulate the accepted socket's peer without opening any external connection.
    if (!trustedSource) f.app.prependListener('request', (req) => {
      Object.defineProperty(req.socket, 'remoteAddress', { value: '192.0.2.200', configurable: true });
    });
    const attempt = (i, ip) => f.client.call('/api/login', 'POST', {
      email: `missing-${i}@example.test`, password: fakeSecret(),
    }, { 'x-forwarded-for': ip });
    for (let i = 0; i < 20; i++) assert.equal((await attempt(i, '198.51.100.1')).status, 401);
    assert.equal((await attempt(20, '198.51.100.1')).status, 429);
    assert.equal((await attempt(21, '198.51.100.2')).status, trustedSource ? 401 : 429);
    f.advance(900001);
    assert.equal((await attempt(22, '198.51.100.1')).status, 401);
  });
}
