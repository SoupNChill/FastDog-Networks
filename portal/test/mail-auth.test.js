import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAuth } from '../src/auth.js';
import { createRateLimits } from '../src/rate-limits.js';
import { createStore, emptyAccounts } from '../src/store.js';
import { createSmtpMailer } from '../src/mailer-smtp.js';
import { createFileMailer } from '../src/mailer-file.js';
import { createInvites } from '../src/invites.js';
import { normalizeEmail } from '../src/tokens.js';
import { temporary, fakeSecret } from './helpers.js';

function setup(t, options = {}) {
  const dataDir = temporary(t), store = createStore(dataDir), delivered = [], logs = [];
  let clock = Date.UTC(2026, 0, 1), broken = false;
  const now = () => clock;
  const mailer = createSmtpMailer({ host: 'mail.example.test', user: 'u', pass: fakeSecret(), from: 'sender@example.test',
    fallback: createFileMailer({ outboxDir: temporary(t) }), now, maxPerHour: options.maxPerHour || 300,
    logger: (entry) => logs.push(entry), deliver: async (message) => { if (broken) throw Error('unavailable'); delivered.push(message); } });
  const auth = createAuth({ store, now, mailer, limits: createRateLimits(now, store),
    sessions: { revokeUser() {} }, config: { origin: 'https://portal.example.test', openSignup: true, signupIpPerHour: 100 } });
  const call = async (path, body) => {
    const response = await auth.handle(path, body, { ip: '127.0.0.1', send: (status, body) => ({ status, body }) });
    await new Promise((resolve) => setImmediate(resolve));
    return response;
  };
  return { store, dataDir, delivered, logs, call, now, advance: (ms) => { clock += ms; }, break: () => { broken = true; } };
}
const resetToken = (message) => new URLSearchParams(new URL(message.message.match(/https:\/\/portal\.example\.test\/login#[^\s]+/)[0]).hash.slice(1)).get('token');

for (const failure of ['recipient_cap', 'rate_cap', 'internal']) test('reset links survive replacement delivery: ' + failure, async (t) => {
  const f = setup(t, { maxPerHour: failure === 'rate_cap' ? 3 : 300 });
  const data = emptyAccounts();
  data.users.push({ id: 'u', email: 'owner@example.test', auth_version: 1 });
  f.store.write('accounts', data);
  const request = () => f.call('/api/password-reset', { email: 'owner@example.test' });
  const count = failure === 'internal' ? 1 : 3;
  for (let i = 0; i < count; i++) assert.equal((await request()).status, 200);
  const token = resetToken(f.delivered.at(-1));
  f.advance(900001);
  if (failure === 'internal') f.break();
  // A different recipient consumes no recipient budget in the global-cap case.
  if (failure === 'rate_cap') {
    const accounts = f.store.read('accounts');
    accounts.users[0].email = 'other@example.test';
    f.store.write('accounts', accounts);
    await f.call('/api/password-reset', { email: 'other@example.test' });
  } else await request();
  assert.ok(f.logs.some((entry) => entry.reason === failure));
  assert.ok(f.store.read('accounts').links.length <= 3);
  assert.equal((await f.call('/api/password-reset/confirm', { token, password: fakeSecret() })).status, 200);
  assert.equal(f.store.read('accounts').links.length, 0);
  for (const message of f.delivered) await assert.rejects(f.call('/api/password-reset/confirm',
    { token: resetToken(message), password: fakeSecret() }), { code: 'unauthorized' });
});

for (const invited of [false, true]) for (const email of ["owner'tag+=_-@example.test", 'owner@bücher.example.test']) {
  test('signup verification and legacy reset deliver normalized address: ' + invited + ' ' + email, async (t) => {
    const f = setup(t), normalized = normalizeEmail(email);
    const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email });
    assert.equal(f.store.read('accounts').invites[0].email, normalized);
    await f.call('/api/signup', { email, password: fakeSecret(), accept_terms: true, ...(invited ? { invite_code: code } : {}) });
    assert.equal(f.delivered.length, 1);
    assert.equal(f.delivered[0].to, normalized);
    assert.ok(f.delivered[0].message.includes('To: ' + normalized + '\r\n'));
    const verification = f.delivered[0].message.match(/https:\/\/portal\.example\.test\/verify-email#[^\s]+/)[0];
    const token = new URLSearchParams(new URL(verification).hash.slice(1)).get('token');
    assert.equal((await f.call('/api/verify-email', { token, password: fakeSecret() })).status, 200);
    const accounts = f.store.read('accounts');
    accounts.users[0].email = email; // Existing accounts can still contain Unicode domains.
    f.store.write('accounts', accounts);
    await f.call('/api/password-reset', { email: normalized });
    assert.equal(f.delivered.length, 2);
    assert.equal(f.delivered[1].to, normalized);
    assert.equal((await f.call('/api/password-reset/confirm', { token: resetToken(f.delivered[1]), password: fakeSecret() })).status, 200);
  });
}

test('shared email validation accepts ASCII atext and rejects unsafe or malformed addresses', () => {
  assert.equal(normalizeEmail("a!#$%&'*+-/=?^_`{|}~.b@example.test"), "a!#$%&'*+-/=?^_`{|}~.b@example.test");
  assert.equal(normalizeEmail('Owner@bücher.example.test'), 'owner@xn--bcher-kva.example.test');
  for (const invited of [false, true]) for (const email of [' a@example.test', 'a@example.test\r\n', 'a\0@example.test', 'a b@example.test',
    '.a@example.test', 'a..b@example.test', 'a.@example.test', 'a@example.test/path', 'a@example.test%00',
    'a@-bad.example.test', 'a@' + 'x'.repeat(64) + '.test', 'a'.repeat(65) + '@example.test', 'ü@example.test',
    'a<b@example.test', 'a"b@example.test']) assert.equal(normalizeEmail(email), null);
});
