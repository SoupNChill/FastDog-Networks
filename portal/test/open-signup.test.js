import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { join } from 'node:path';
import { createApp } from '../src/app.js';
import { createInvites } from '../src/invites.js';
import { emptyAccounts } from '../src/store.js';
import { loadDisposable, emailDomain, parentDomains, baseDomain, BIGMAIL } from '../src/signup-guard.js';
import { start } from '../server.js';
import { fixture, fakeSecret, browser, listen, origin, temporary, request } from './helpers.js';

async function open(t, config = {}) {
  const logs = [];
  const f = await fixture(t, { openSignup: true, logger: (entry) => logs.push(entry), ...config });
  const signup = async (email, extra = {}) => {
    const result = await f.client.call('/api/signup', 'POST', { email, password: fakeSecret(), ...extra });
    assert.equal(result.status, 200);
    assert.deepEqual(result.data, { ok: true });
    return result;
  };
  const accounts = () => f.store.read('accounts', emptyAccounts());
  const reasons = () => logs.filter((e) => e.event === 'signup').map((e) => e.reason ?? e.outcome);
  return { ...f, logs, signup, accounts, reasons };
}

test('vendored disposable list keeps its CC0 provenance header and parses to domains', () => {
  const text = readFileSync(new URL('../src/data/disposable-domains.txt', import.meta.url), 'utf8');
  assert.match(text, /github\.com\/disposable-email-domains\/disposable-email-domains/);
  assert.match(text, /CC0/);
  const list = loadDisposable();
  assert.ok(list.size >= 100);
  for (const name of ['mailinator.com', 'guerrillamail.com', 'yopmail.com', '10minutemail.com']) assert.ok(list.has(name), name);
  for (const name of list) assert.match(name, /^[a-z0-9-]+(\.[a-z0-9-]+)+$/);
  for (const name of BIGMAIL) assert.ok(!list.has(name), name);
  const script = readFileSync(new URL('../bin/update-disposable.sh', import.meta.url), 'utf8');
  assert.match(script, /never touches the network/);
  assert.doesNotMatch(script, /\b(curl|wget)\b/);
});

test('domain helpers normalize IDN and trailing dots, list parents and approximate the registrable domain', () => {
  assert.equal(emailDomain('a@Sub.Example.Test.'), 'sub.example.test');
  assert.equal(emailDomain('a@bücher.example'), 'xn--bcher-kva.example');
  for (const bad of ['a@-bad-.example', 'a@x_y.example', 'nobody', null, '@example.test']) assert.equal(emailDomain(bad), null, String(bad));
  assert.deepEqual(parentDomains('a.b.example.test'), ['a.b.example.test', 'b.example.test', 'example.test']);
  assert.equal(baseDomain('mail.a.example.test'), 'example.test');
  assert.equal(baseDomain('mail.example.co.uk'), 'example.co.uk');
  assert.equal(baseDomain('example.test'), 'example.test');
});

test('OPEN_SIGNUP off keeps invites required and /api/me reports open_signup false', async (t) => {
  const f = await fixture(t);
  assert.equal((await f.client.call('/api/me')).data.open_signup, false);
  const result = await f.client.call('/api/signup', 'POST', { email: 'new@example.test', password: fakeSecret() });
  assert.deepEqual(result.data, { ok: true });
  assert.equal(f.store.read('accounts', emptyAccounts()).users.length, 0);
  assert.equal(f.messages.length, 0);
});

test('open sign-up creates an unverified trial tenant with one hostname and logs no email', async (t) => {
  const f = await open(t);
  assert.equal((await f.client.call('/api/me')).data.open_signup, true);
  await f.signup('New@Example.test');
  const { users, tenants } = f.accounts();
  assert.equal(users.length, 1);
  assert.equal(users[0].email, 'new@example.test');
  assert.equal(users[0].email_verified_at, null);
  assert.deepEqual({ ...tenants[0], id: undefined }, { id: undefined, name: '', plan: 'trial', hostname_limit: 1, status: 'active', source: 'open' });
  assert.deepEqual(f.messages.map((m) => [m.to, m.kind]), [['new@example.test', 'verify-email']]);
  assert.deepEqual(f.reasons(), ['created']);
  assert.ok(!JSON.stringify(f.logs).includes('example.test'));
  // The same address again is generic and creates nothing.
  await f.signup('new@example.test');
  assert.equal(f.accounts().users.length, 1);
  assert.deepEqual(f.reasons(), ['created', 'exists']);
});

test('open sign-up restrictions are fixed; invites keep their own path', async (t) => {
  const f = await open(t);
  await f.signup('open@example.test');
  const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email: 'invited@example.test', plan: 'pro', hostnameLimit: 7 });
  await f.signup('invited@example.test', { invite_code: code });
  // A wrong invite never falls back to open sign-up.
  await f.signup('wrong@example.test', { invite_code: fakeSecret() });
  const { users, tenants, invites } = f.accounts();
  assert.deepEqual(users.map((u) => u.email), ['open@example.test', 'invited@example.test']);
  assert.deepEqual(tenants.map((x) => [x.plan, x.hostname_limit, x.source]), [['trial', 1, 'open'], ['pro', 7, undefined]]);
  assert.equal(invites[0].tenant_id, tenants[1].id);
  assert.deepEqual(f.reasons(), ['created']);
});

test('disposable domains and their subdomains are refused generically in open mode only', async (t) => {
  const f = await open(t, { signupIpPerHour: 100, signupDisposable: new Set(['blocked.example.test', 'blocked.example.invalid']) });
  for (const email of ['a@blocked.example.test', 'b@inbox.BLOCKED.example.test', 'c@blocked.example.invalid', 'd@-bad-.example']) await f.signup(email);
  assert.equal(f.accounts().users.length, 0);
  assert.equal(f.messages.length, 0);
  assert.deepEqual(f.reasons(), ['disposable', 'disposable', 'disposable', 'invalid_domain']);
  assert.ok(!JSON.stringify(f.logs).includes('blocked.example'));
  // Disposable blocks spend no domain or global budget.
  assert.deepEqual(Object.keys(f.store.read('rate_limits', {})).filter((k) => !k.startsWith('signup:')), []);
  // Invite sign-ups are unaffected by the disposable list.
  const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email: 'ok@blocked.example.test' });
  await f.signup('ok@blocked.example.test', { invite_code: code });
  assert.equal(f.accounts().users.length, 1);
});

test('per-domain limits share a budget across subdomains, large providers get their own, and reset daily', async (t) => {
  const f = await open(t, { signupIpPerHour: 100, signupDomainPerDay: 2, signupBigmailPerDay: 3, signupBigmail: new Set(['mail.example.invalid']) });
  for (const email of ['a@example.org', 'b@mail.example.org', 'c@other.example.org']) await f.signup(email);
  for (const email of ['a@mail.example.invalid', 'b@mail.example.invalid', 'c@mail.example.invalid', 'd@mail.example.invalid']) await f.signup(email);
  assert.deepEqual(f.accounts().users.map((u) => u.email), ['a@example.org', 'b@mail.example.org', 'a@mail.example.invalid', 'b@mail.example.invalid', 'c@mail.example.invalid']);
  assert.deepEqual(f.reasons(), ['created', 'created', 'domain_limit', 'created', 'created', 'created', 'domain_limit']);
  const saved = f.store.read('rate_limits', {});
  assert.equal(saved['signup-domain:example.org'].count, 2);
  assert.ok(!JSON.stringify(saved).includes('@'), 'limit keys never hold an address');
  f.advance(86400000);
  await f.client.call('/api/me');
  await f.signup('d@example.org');
  assert.equal(f.accounts().users.length, 6);
});

test('the global daily limit refuses before creating domain keys and emits an alert', async (t) => {
  const f = await open(t, { signupIpPerHour: 100, signupGlobalPerDay: 2 });
  for (const email of ['a@one.example', 'b@two.example', 'c@three.example']) await f.signup(email);
  assert.equal(f.accounts().users.length, 2);
  assert.deepEqual(f.reasons(), ['created', 'created', 'global_limit']);
  assert.equal(f.store.read('rate_limits', {})['signup-domain:three.example'], undefined);
  assert.equal(f.logs.find((e) => e.reason === 'global_limit').alert, 'signup_global_limit');
  assert.equal(f.logs.find((e) => e.reason === 'global_limit').level, 'error');
});

test('the per-IP sign-up limit is persistent and configurable', async (t) => {
  const f = await open(t, { signupIpPerHour: 2 });
  await f.signup('a@example.test');
  await f.signup('b@example.test');
  assert.equal((await f.client.call('/api/signup', 'POST', { email: 'c@example.test', password: fakeSecret() })).status, 429);
  assert.ok(Object.keys(f.store.read('rate_limits', {})).some((k) => k.startsWith('signup:')));
  // A restarted portal on the same state keeps the budget spent.
  const restarted = createApp({ dataDir: f.dataDir, now: f.now, edge: f.edge, mailer: { async send() {} }, config: { origin, openSignup: true, signupIpPerHour: 2 } });
  const client = browser(await listen(t, restarted));
  await client.call('/api/me');
  assert.equal((await client.call('/api/signup', 'POST', { email: 'd@example.test', password: fakeSecret() })).status, 429);
  f.advance(3600000);
  await client.call('/api/me');
  assert.equal((await client.call('/api/signup', 'POST', { email: 'd@example.test', password: fakeSecret() })).status, 200);
});

test('open tenants get the smaller connect-token budget', async (t) => {
  const f = await fixture(t);
  const { client } = await f.seed();
  const data = f.store.read('accounts', emptyAccounts());
  data.tenants[0].source = 'open';
  f.store.write('accounts', data);
  await f.edge.createHostname(data.tenants[0].id, 'app.example.test', 1);
  await f.edge.verifyHostname(data.tenants[0].id, 'app.example.test');
  for (let i = 0; i < 3; i++) assert.equal((await client.call('/api/hostnames/app.example.test/connect-token', 'POST')).status, 201);
  assert.equal((await client.call('/api/hostnames/app.example.test/connect-token', 'POST')).status, 429);
});

test('unverified accounts cannot create hostnames, connect tokens, API keys or domain requests', async (t) => {
  const f = await fixture(t);
  const { client, user, password } = await f.seed(0, false);
  await f.edge.createHostname(user.tenant_id, 'app.example.test', 1);
  await f.edge.verifyHostname(user.tenant_id, 'app.example.test');
  const before = f.calls.length;
  for (const [path, body] of [['/api/hostnames', { hostname: 'new.example.test' }], ['/api/hostnames/app.example.test/connect-token', {}],
    ['/api/keys', { scopes: ['status:read'], password }], ['/api/domain-requests', { name: 'new.example.test' }]]) {
    const result = await client.call(path, 'POST', body);
    assert.equal(result.status, 401, path);
    assert.deepEqual(result.data, { error: 'unauthorized' });
  }
  assert.ok(!f.calls.slice(before).some(([name]) => name === 'create'));
  assert.deepEqual(f.store.read('connect_tokens', []), []);
  assert.deepEqual(f.store.read('api_keys', []), []);
  assert.deepEqual(f.store.read('domain_requests', []), []);
  assert.equal(f.messages.length, 0);
});

test('createApp and server start validate open sign-up settings', async (t) => {
  const dataDir = temporary(t);
  for (const bad of [{ openSignup: '1' }, { openSignupPlan: 'starter' }, { openSignupHostnameLimit: 2 }, { openConnectTokensPerHour: 4 }, { openSignupHostnameLimit: 0 }, { openSignupPlan: ' ' }, { openConnectTokensPerHour: 1.5 },
    { signupIpPerHour: 0 }, { signupDomainPerDay: -1 }, { signupBigmailPerDay: 'x' }, { signupGlobalPerDay: 1e6 }]) {
    assert.throws(() => createApp({ dataDir, config: { origin, ...bad } }), /Invalid open sign-up settings/, JSON.stringify(bad));
  }
  const env = { STATE_DIRECTORY: dataDir, PORTAL_ORIGIN: origin, PORTAL_KEY: fakeSecret() };
  assert.throws(() => start({ ...env, OPEN_SIGNUP_HOSTNAME_LIMIT: '0' }), /Invalid open sign-up settings/);
  assert.throws(() => start({ ...env, SIGNUP_GLOBAL_PER_DAY: 'many' }), /Invalid open sign-up settings/);
  t.mock.method(console, 'log', () => {});
  const probe = createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  for (const [flag, expected] of [[undefined, false], ['1', true], ['true', false]]) {
    const app = start({ ...env, PORTAL_PORT: String(port), ...(flag === undefined ? {} : { OPEN_SIGNUP: flag }) });
    await once(app, 'listening');
    const me = await request(port, '/api/me');
    await new Promise((resolve) => { app.close(resolve); app.closeAllConnections(); });
    assert.equal(me.data.open_signup, expected, String(flag));
  }
  assert.ok(readFileSync(join(dataDir, 'sessions.json'), 'utf8'));
});


test('flag-off signup IP limits reset after restart', async (t) => {
  const f = await fixture(t);
  const body = { email: 'invite@example.test', password: fakeSecret() };
  for (let i = 0; i < 3; i++) assert.equal((await f.client.call('/api/signup', 'POST', body)).status, 200);
  assert.equal((await f.client.call('/api/signup', 'POST', body)).status, 429);
  assert.deepEqual(f.store.read('rate_limits', {}), {});
  const restarted = createApp({ dataDir: f.dataDir, now: f.now, edge: f.edge, mailer: { async send() {} }, config: { origin } });
  const client = browser(await listen(t, restarted));
  await client.call('/api/me');
  const invite_code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email: body.email });
  assert.equal((await client.call('/api/signup', 'POST', { ...body, invite_code })).status, 200);
  assert.equal(f.store.read('accounts', emptyAccounts()).users.length, 1);
});

test('open verification replaces the registration password and revokes pre-verification sessions', async (t) => {
  const f = await open(t);
  const email = 'owner@example.test', password = fakeSecret(), replacement = fakeSecret();
  await f.signup(email, { password });
  const token = new URLSearchParams(new URL(f.messages[0].link).hash.slice(1)).get('token');
  assert.equal(new URLSearchParams(new URL(f.messages[0].link).hash.slice(1)).get('setup'), '1');
  assert.equal((await f.client.call('/api/login', 'POST', { email, password })).status, 200);
  await f.client.call('/api/me');
  assert.equal((await f.client.call('/api/verify-email', 'POST', { token })).status, 401);
  assert.equal((await f.client.call('/api/verify-email', 'POST', { token, password: replacement })).status, 200);
  assert.equal((await f.client.call('/api/me')).data.tenant, null);
  assert.equal((await f.client.call('/api/login', 'POST', { email, password })).status, 401);
  assert.equal((await f.client.call('/api/login', 'POST', { email, password: replacement })).status, 200);
  await f.client.call('/api/me');
  assert.equal((await f.client.call('/api/verify-email', 'POST', { token, password })).status, 401);
  assert.equal(f.accounts().users[0].auth_version, 2);
  assert.equal((await f.client.call('/api/keys', 'POST', { scopes: ['status:read'], password: replacement })).status, 403);
  assert.deepEqual(f.store.read('api_keys', []), []);
});

test('expired unverified open registrations can be reclaimed without creating another tenant', async (t) => {
  const f = await open(t);
  await f.signup('owner@example.test');
  const old = new URLSearchParams(new URL(f.messages[0].link).hash.slice(1)).get('token');
  const tenant = f.accounts().tenants[0].id;
  f.advance(3600001);
  await f.client.call('/api/me');
  await f.signup('owner@example.test');
  assert.equal(f.accounts().users.length, 1);
  assert.equal(f.accounts().tenants[0].id, tenant);
  assert.equal(f.messages.length, 2);
  assert.equal((await f.client.call('/api/verify-email', 'POST', { token: old, password: fakeSecret() })).status, 401);
  assert.deepEqual(f.reasons(), ['created', 'reclaimed']);
});
