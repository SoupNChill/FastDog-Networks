import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAuth } from '../src/auth.js';
import { createApp } from '../src/app.js';
import { createStore, emptyAccounts } from '../src/store.js';
import { createSessions } from '../src/sessions.js';
import { createRateLimits } from '../src/rate-limits.js';
import { createSignupGuard } from '../src/signup-guard.js';
import { verifyPassword } from '../src/passwords.js';
import { temporary, fakeSecret, origin } from './helpers.js';

test('global refusal allocates no domain keys and refunds remove empty entries', (t) => {
  const store = createStore(temporary(t)), now = () => 1000;
  const limits = createRateLimits(now, store);
  const guard = createSignupGuard({ limits, disposable: new Set(), config: {
    signupGlobalPerDay: 1, signupDomainPerDay: 1, signupBigmailPerDay: 1,
  } });
  assert.equal(guard.check('first@example.test'), null);
  for (let i = 0; i < 100; i++) assert.equal(guard.check(`next@domain${i}.invalid`), 'global_limit');
  assert.deepEqual(Object.keys(store.read('rate_limits', {})).sort(), ['signup-domain:example.test', 'signup-global']);
  limits.refund('signup-global', true);
  assert.equal(store.read('rate_limits', {})['signup-global'], undefined);
  assert.equal(guard.check('second@example.test'), 'domain_limit');
  assert.equal(store.read('rate_limits', {})['signup-global'], undefined);
  limits.take('memory', 1, 1000);
  limits.refund('memory');
  limits.take('memory', 1, 1000);
});

test('conflicting self-serve limits fail before starting a server', (t) => {
  const dataDir = temporary(t);
  for (const settings of [{ openSignupPlan: 'starter' }, { openSignupHostnameLimit: 2 }, { openConnectTokensPerHour: 4 }]) {
    assert.throws(() => createApp({ dataDir, config: { origin, ...settings } }), /Invalid open sign-up settings/);
  }
});

test('open verification secures the account and expired signup preserves its tenant', async (t) => {
  const store = createStore(temporary(t));
  let time = 1000;
  const now = () => time, messages = [];
  const sessions = createSessions(store, now), limits = createRateLimits(now, store);
  const auth = createAuth({ store, sessions, limits, now, mailer: { async send(mail) { messages.push(mail); } }, config: {
    origin, openSignup: true, signupIpPerHour: 100, signupGlobalPerDay: 100, signupDomainPerDay: 20, signupBigmailPerDay: 20,
  } });
  const context = { ip: '127.0.0.1', session: sessions.create(), send: (status, body) => ({ status, body }) };
  const email = 'owner@example.test', password = fakeSecret(), replacement = fakeSecret();
  const read = () => store.read('accounts', emptyAccounts());
  const linkToken = (mail) => new URLSearchParams(new URL(mail.link).hash.slice(1)).get('token');
  await auth.handle('/api/signup', { email, password }, context);
  const tenant = read().tenants[0].id, old = linkToken(messages[0]);
  assert.equal(read().tenants[0].plan, 'trial');
  assert.equal(read().tenants[0].hostname_limit, 1);
  const session = sessions.create(read().users[0]);
  time += 3600001;
  await auth.handle('/api/signup', { email, password }, context);
  assert.equal(read().tenants.length, 1);
  assert.equal(read().tenants[0].id, tenant);
  assert.equal(auth.identity(session), null);
  await assert.rejects(auth.handle('/api/verify-email', { token: old, password: replacement }, context), { code: 'unauthorized' });
  const token = linkToken(messages[1]);
  await assert.rejects(auth.handle('/api/verify-email', { token }, context), { code: 'unauthorized' });
  const before = sessions.create(read().users[0]);
  await auth.handle('/api/verify-email', { token, password: replacement }, context);
  assert.equal(auth.identity(before), null);
  assert.equal(sessions.get(before.cookie), null);
  assert.equal(await verifyPassword(password, read().users[0].password_hash), false);
  assert.equal(await verifyPassword(replacement, read().users[0].password_hash), true);
  assert.equal(read().users[0].auth_version, 3);
  assert.equal(read().links.length, 0);
  await auth.handle('/api/signup', { email, password }, context);
  assert.equal(messages.length, 2, 'verified account cannot be reclaimed');
});


test('flag-off IP budgets reset on restart and never persist', async (t) => {
  const store = createStore(temporary(t)), now = () => 1000;
  const sessions = createSessions(store, now);
  const context = { ip: '127.0.0.1', session: sessions.create(), send: (status) => status };
  const restart = () => createAuth({ store, sessions, limits: createRateLimits(now, store), now,
    mailer: { async send() {} }, config: { origin, openSignup: false } });
  const auth = restart();
  for (let i = 0; i < 3; i++) assert.equal(await auth.handle('/api/signup', {}, context), 200);
  await assert.rejects(auth.handle('/api/signup', {}, context), { code: 'rate_limited' });
  assert.deepEqual(store.read('rate_limits', {}), {});
  assert.equal(await restart().handle('/api/signup', {}, context), 200);
});
