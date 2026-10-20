import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { join } from 'node:path';
import { createOwnerNotify, ownerNotifyConfig, maskEmail } from '../src/owner-notify.js';
import { renderMail, mailKinds } from '../src/mail-templates.js';
import { buildMessage, createSmtpMailer } from '../src/mailer-smtp.js';
import { createFileMailer } from '../src/mailer-file.js';
import { createMailBudget } from '../src/mail-budget.js';
import { createStore, emptyAccounts } from '../src/store.js';
import { createInvites } from '../src/invites.js';
import { sweepTrials } from '../src/trials.js';
import { digest } from '../src/tokens.js';
import { start } from '../server.js';
import { fixture, fakeSecret, temporary, tids, linkToken, origin, browser } from './helpers.js';

const OWNER = 'owner@example.test';
const DAY = 86400000;
const tick = () => new Promise((resolve) => setImmediate(resolve));
// Every owner_notify log line from every test here; none may contain an address.
const allLogs = [];

// Fake clock and timers: advance(ms) fires due timers in order; cancelled timers never fire.
function harness(t, options = {}) {
  const dir = options.dir ?? temporary(t);
  const store = createStore(dir);
  let clock = options.clock ?? Date.parse('2026-10-20T22:05:00Z');
  const timers = new Set();
  const schedule = (fn, ms) => { const timer = { fn, at: clock + ms, unref() { timer.unrefd = true; } }; timers.add(timer); return timer; };
  const cancel = (timer) => timers.delete(timer);
  const sent = [];
  const logs = [];
  const mailer = options.mailer ?? { async send(message) { sent.push(message); } };
  const owner = createOwnerNotify({ mailer, to: OWNER, store, now: () => clock, schedule, cancel,
    logger: (entry) => { logs.push(entry); allLogs.push(entry); }, ...options.config });
  t.after(() => owner.stop());
  const advance = async (ms) => {
    const target = clock + ms;
    for (;;) {
      const due = [...timers].filter((timer) => timer.at <= target).sort((a, b) => a.at - b.at)[0];
      if (!due) break;
      timers.delete(due);
      clock = due.at;
      due.fn();
      await tick();
    }
    clock = target;
  };
  return { owner, dir, store, sent, logs, timers, advance, now: () => clock };
}
const signup = (n, extra = {}) => ({ type: 'signup', source: 'open', tenant_id: `t_${String(n).padStart(20, 'a')}`, user_id: `user-${n}`, email: `user${n}@example.com`, ...extra });

test('config: disabled when unset; parses events, caps and batch window with safe defaults', () => {
  assert.deepEqual(ownerNotifyConfig({}), { to: null, events: ['signup', 'verify', 'trial_pause'], maxPerHour: 3, batchMs: 900000, showEmail: false });
  assert.equal(ownerNotifyConfig({ OWNER_NOTIFY_EMAIL: '  ' }).to, null);
  const parsed = ownerNotifyConfig({ OWNER_NOTIFY_EMAIL: OWNER, OWNER_NOTIFY_EVENTS: ' Verify, bogus,trial_pause', OWNER_NOTIFY_MAX_PER_HOUR: '2',
    OWNER_NOTIFY_BATCH_MINUTES: '5', OWNER_NOTIFY_SHOW_EMAIL: '1' });
  assert.deepEqual(parsed, { to: OWNER, events: ['verify', 'trial_pause'], maxPerHour: 2, batchMs: 300000, showEmail: true });
  for (const [value, expected] of [['9', 3], ['0', 3], ['x', 3], ['-1', 3], ['1', 1]]) assert.equal(ownerNotifyConfig({ OWNER_NOTIFY_MAX_PER_HOUR: value }).maxPerHour, expected, value);
  for (const [value, expected] of [['0', 15], ['500', 120], ['abc', 15], ['120', 120]]) assert.equal(ownerNotifyConfig({ OWNER_NOTIFY_BATCH_MINUTES: value }).batchMs, expected * 60000, value);
  assert.equal(ownerNotifyConfig({ OWNER_NOTIFY_SHOW_EMAIL: 'true' }).showEmail, false);
});

test('disabled notifier is a no-op with the same shape; an invalid address logs once', async (t) => {
  const dir = temporary(t);
  const store = createStore(dir);
  const sent = [], logs = [];
  const mailer = { async send(message) { sent.push(message); } };
  const off = createOwnerNotify({ mailer, store, ...ownerNotifyConfig({}), logger: (entry) => logs.push(entry) });
  assert.deepEqual(Object.keys(off).sort(), ['flush', 'notify', 'stop']);
  assert.equal(off.notify(signup(1)), undefined);
  await off.flush();
  off.stop();
  const bad = createOwnerNotify({ mailer, store, to: 'not an address', logger: (entry) => { logs.push(entry); allLogs.push(entry); } });
  for (let i = 0; i < 3; i++) bad.notify(signup(i));
  await bad.flush();
  await tick();
  assert.deepEqual(sent, []);
  assert.deepEqual(logs, [{ event: 'owner_notify', result: 'disabled', reason: 'invalid_address' }]);
  assert.equal(existsSync(join(dir, 'owner_notify.json')), false);
});

test('first event is sent on the next turn with a Mountain-time line and a masked address', async (t) => {
  const h = harness(t);
  assert.equal(h.owner.notify(signup(1)), undefined);
  assert.deepEqual(h.sent, [], 'never inline with the caller');
  await tick();
  assert.deepEqual(h.sent, [{ to: OWNER, kind: 'owner-event', count: 1,
    lines: [`New sign-up (open): u***@example.com - tenant ${signup(1).tenant_id} - 2026-10-20 16:05 MT`] }]);
  assert.ok(h.timers.size === 1 && [...h.timers].every((timer) => timer.unrefd));
  assert.equal(maskEmail('pat@example.com'), 'p***@example.com');
});

test('events filter, full-address option and event line formats', async (t) => {
  const h = harness(t, { config: { events: ['verify', 'trial_pause'], showEmail: true, batchMs: 60000 } });
  h.owner.notify(signup(1));
  h.owner.notify({ type: 'unknown', tenant_id: tids[0] });
  h.owner.notify(null);
  await tick();
  assert.deepEqual(h.sent, []);
  h.owner.notify({ type: 'verify', tenant_id: tids[0], user_id: 'user-1', email: 'user1@example.com' });
  await tick();
  h.owner.notify({ type: 'trial_pause', tenant_id: tids[1], paused_at: '2026-10-20T22:05:00.000Z', email: 'user2@example.com' });
  h.owner.notify({ type: 'trial_pause', tenant_id: tids[2] });
  await h.advance(60000);
  assert.deepEqual(h.sent.map((m) => m.lines), [
    [`Email verified: user1@example.com - tenant ${tids[0]} - 2026-10-20 16:05 MT`],
    ['2 new events', `Trial paused: tenant ${tids[1]} (user2@example.com) - 2026-10-20 16:05 MT`, `Trial paused: tenant ${tids[2]} - 2026-10-20 16:05 MT`]]);
  assert.deepEqual(h.sent.map((m) => m.count), [1, 2]);
});

test('coalescing: one mail at the end of the window, then quiet sends immediately again', async (t) => {
  const h = harness(t);
  h.owner.notify(signup(1));
  await tick();
  h.owner.notify(signup(2));
  await h.advance(60000);
  h.owner.notify(signup(3));
  await tick();
  assert.equal(h.sent.length, 1);
  await h.advance(14 * 60000);
  assert.equal(h.sent.length, 2);
  assert.equal(h.sent[1].count, 2);
  assert.equal(h.sent[1].lines[0], '2 new events');
  // The next window closes with nothing queued; the following event goes out straight away.
  await h.advance(15 * 60000);
  assert.equal(h.sent.length, 2);
  h.owner.notify(signup(4));
  await tick();
  assert.equal(h.sent.length, 3);
  assert.equal(h.sent[2].count, 1);
});

test('at most three owner mails per rolling hour; overflow carries over to the next slot', async (t) => {
  const h = harness(t, { config: { batchMs: 60000, maxPerHour: 9 } });
  h.owner.notify(signup(1));
  await tick();
  for (let i = 2; i <= 4; i++) { h.owner.notify(signup(i)); await h.advance(60000); }
  assert.equal(h.sent.length, 3, 'capped at 3 even when configured higher');
  h.owner.notify(signup(5));
  await h.advance(55 * 60000);
  assert.equal(h.sent.length, 3);
  await h.advance(2 * 60000);
  assert.equal(h.sent.length, 4);
  assert.deepEqual(h.sent[3].lines.slice(0, 1), ['2 new events']);
  assert.deepEqual(h.logs.filter((e) => e.result === 'sent').map((e) => e.count), [1, 1, 1, 2]);
});

test('pending queue is capped at 200 events and overflow is logged by reason only', async (t) => {
  const h = harness(t);
  h.owner.notify(signup(0));
  await tick();
  for (let i = 1; i <= 205; i++) h.owner.notify(signup(i));
  assert.equal(h.logs.filter((e) => e.reason === 'owner_queue_full').length, 5);
  await h.owner.flush();
  assert.equal(h.sent.length, 2);
  assert.equal(h.sent[1].count, 200);
  assert.equal(h.sent[1].lines.length, 201);
  assert.doesNotThrow(() => renderMail({ kind: 'owner-event', lines: h.sent[1].lines, count: 200 }));
});

test('dedupe keys survive a restart, are pruned after 8 days and hold no addresses', async (t) => {
  const first = harness(t);
  first.store.write('owner_notify', { sent: { 'signup:t_old': first.now() - 9 * DAY } });
  first.owner.notify(signup(1));
  first.owner.notify(signup(1));
  first.owner.notify({ type: 'verify', tenant_id: tids[0], user_id: 'user-1', email: 'user1@example.com' });
  await tick();
  await first.owner.flush();
  assert.equal(first.sent.reduce((n, m) => n + m.count, 0), 2);
  first.owner.stop();
  const second = harness(t, { dir: first.dir, clock: first.now() + DAY });
  second.owner.notify(signup(1));
  second.owner.notify({ type: 'verify', tenant_id: tids[0], user_id: 'user-1', email: 'user1@example.com' });
  // A reclaim is keyed by user and minute, so a later reclaim is reported.
  second.owner.notify(signup(1, { reclaimed: true }));
  await tick();
  assert.equal(second.sent.length, 1);
  assert.match(second.sent[0].lines[0], /^New sign-up \(open, reclaimed\): u\*\*\*@example\.com/);
  const state = first.store.read('owner_notify');
  assert.deepEqual(Object.keys(state.sent).sort(), [`reclaim:user-1:${Math.floor(second.now() / 60000)}`, `signup:${signup(1).tenant_id}`, 'verify:user-1'].sort());
  assert.ok(Object.values(state.sent).every(Number.isFinite));
  assert.ok(!JSON.stringify(state).includes('@'));
});

test('a corrupt or wrongly shaped state file fails open and is replaced', async (t) => {
  for (const content of ['{not json', '[]', '{"sent":{"x":"y"}}']) {
    const h = harness(t);
    writeFileSync(join(h.dir, 'owner_notify.json'), content);
    h.owner.notify(signup(1));
    await tick();
    assert.equal(h.sent.length, 1, content);
    assert.ok(h.logs.some((e) => e.reason === 'state_unreadable'), content);
    assert.ok(Object.hasOwn(h.store.read('owner_notify').sent, `signup:${signup(1).tenant_id}`), content);
  }
});

test('a mailer that throws or rejects is contained and logged by reason only', async (t) => {
  for (const mailer of [{ send() { throw new Error('boom'); } }, { async send() { throw new Error('boom'); } }, { enqueue() { throw new Error('boom'); } }]) {
    const h = harness(t, { mailer });
    assert.doesNotThrow(() => h.owner.notify(signup(1)));
    await tick(); await tick();
    assert.deepEqual(h.logs.filter((e) => e.result === 'failed'), [{ event: 'owner_notify', result: 'failed', reason: 'send_failed', count: 1 }]);
  }
  const queued = [];
  const h = harness(t, { mailer: { enqueue(message) { queued.push(message); }, send() { throw new Error('enqueue preferred'); } } });
  h.owner.notify(signup(1));
  await tick();
  assert.equal(queued.length, 1);
});

test('notify() never reads the state file on the request path; persisted dedupe is applied by the worker', async (t) => {
  const first = harness(t);
  first.store.write('owner_notify', { sent: { [`signup:${signup(1).tenant_id}`]: first.now() } });
  const store = createStore(first.dir);
  let reads = 0;
  const spy = { read: (...args) => { reads++; return store.read(...args); }, write: (...args) => store.write(...args) };
  const sent = [];
  const owner = createOwnerNotify({ mailer: { async send(message) { sent.push(message); } }, to: OWNER, store: spy, now: first.now,
    schedule: () => ({ unref() {} }), cancel: () => {} });
  t.after(() => owner.stop());
  owner.notify(signup(1));
  owner.notify(signup(2));
  owner.notify(signup(2));
  assert.equal(reads, 0, 'no file read inside notify()');
  await tick();
  assert.ok(reads >= 1, 'the worker reads the dedupe state');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].count, 1, 'signup 1 was already sent by an earlier process; signup 2 is sent once');
  assert.ok(sent[0].lines[0].includes(signup(2).tenant_id));
  // A batch that is entirely already-sent sends nothing and uses no slot of the hourly cap.
  owner.notify(signup(1));
  await owner.flush();
  assert.equal(sent.length, 1);
});

test('enqueue hand-off is logged as queued, not sent', async (t) => {
  const h = harness(t, { mailer: { enqueue() {} } });
  h.owner.notify(signup(1));
  await tick(); await tick();
  assert.deepEqual(h.logs, [{ event: 'owner_notify', result: 'queued', count: 1 }]);
});

// ---- Templates and mailers ----

test('owner templates take validated lines and use fixed subjects with an operator footer', () => {
  assert.deepEqual(mailKinds, ['verify-email', 'password-reset', 'invite', 'domain-request', 'owner-event', 'owner-digest']);
  const one = renderMail({ kind: 'owner-event', lines: ['Email verified: Zoë - tenant t_x'] });
  assert.equal(one.subject, 'FastDog: new account activity');
  assert.equal(renderMail({ kind: 'owner-event', lines: ['a'], count: 1 }).subject, 'FastDog: new account activity');
  assert.equal(renderMail({ kind: 'owner-event', lines: ['3 new events', 'a', 'b', 'c'], count: 3 }).subject, 'FastDog: 3 new events');
  assert.ok(one.text.startsWith('Email verified: Zoë - tenant t_x\n'));
  assert.match(one.text, /Operator notice/);
  assert.doesNotMatch(one.text, /did not expect/);
  assert.equal(renderMail({ kind: 'owner-digest', lines: ['x'] }).subject, 'FastDog daily summary');
  assert.equal(renderMail({ kind: 'owner-digest', lines: ['x'], date: '2026-10-20' }).subject, 'FastDog daily summary 2026-10-20');
  // Bidi override, line separator and zero-width space are rejected along with C0 controls.
  const invisible = [0x202e, 0x2028, 0x200b].map((code) => ({ lines: [`a${String.fromCharCode(code)}b`] }));
  for (const bad of [{ lines: [] }, { lines: 'x' }, { lines: [1] }, { lines: ['a\rb'] }, { lines: ['a\nb'] }, { lines: ['a\0b'] }, { lines: ['\x1b[31m'] },
    ...invisible, { lines: ['x'.repeat(201)] }, { lines: Array(301).fill('x') }, { lines: ['x'], count: 0 }, { lines: ['x'], count: 'many' }]) {
    assert.throws(() => renderMail({ kind: 'owner-event', ...bad }), /Invalid mail content/, JSON.stringify(bad));
  }
  for (const date of ['2026-1-2', 'today', '2026-10-20\r\nBcc: x']) assert.throws(() => renderMail({ kind: 'owner-digest', lines: ['x'], date }), /Invalid mail content/);
  assert.doesNotThrow(() => renderMail({ kind: 'owner-event', lines: Array(300).fill('x'.repeat(200)) }));
  // Existing kinds are unchanged and still require a link.
  assert.throws(() => renderMail({ kind: 'verify-email', lines: ['x'] }), /Invalid mail content/);
  const rendered = renderMail({ kind: 'owner-event', lines: ['.hidden line', 'ok'] });
  const message = buildMessage({ from: 'noreply@example.invalid', to: OWNER, subject: rendered.subject, text: rendered.text,
    date: new Date(0).toUTCString(), messageId: '<id@example.invalid>' });
  assert.ok(message.includes('\r\n\r\n..hidden line\r\nok\r\n'));
});

function smtp(t) {
  const outboxDir = temporary(t);
  const delivered = [];
  const logs = [];
  const mailer = createSmtpMailer({ host: 'mail.example.test', user: 'u', pass: fakeSecret(), from: 'noreply@example.invalid',
    fallback: createFileMailer({ outboxDir }), logger: (entry) => logs.push(entry), deliver: async (options) => { delivered.push(options.message); } });
  const outbox = () => readdirSync(outboxDir).filter((name) => name.endsWith('.json')).map((name) => readFileSync(join(outboxDir, name), 'utf8'));
  return { mailer, delivered, outbox, logs };
}

test('smtp: owner kinds need no link, go through the recipient budget and leave no lines in audit or fallback records', async (t) => {
  const m = smtp(t);
  const lines = ['New sign-up (open): u***@example.com - tenant t_secretline'];
  const results = [];
  for (let i = 0; i < 4; i++) results.push(await m.mailer.send({ to: OWNER, kind: 'owner-event', lines, count: 1 }));
  assert.deepEqual(results.map((r) => r.delivered), ['smtp', 'smtp', 'smtp', 'failed']);
  assert.equal(results[3].reason, 'recipient_cap');
  assert.ok(m.delivered[0].includes('Subject: FastDog: new account activity\r\n'));
  assert.ok(m.delivered[0].includes('t_secretline'));
  const invalid = await m.mailer.send({ to: OWNER, kind: 'owner-event', lines: ['bad\r\nBcc: x'] });
  assert.deepEqual(invalid, { delivered: 'failed', reason: 'invalid_message' });
  const records = m.outbox().map((text) => JSON.parse(text));
  assert.equal(records.length, 5);
  for (const record of records) assert.deepEqual(Object.keys(record).sort(), ['kind', 'status', 'to']);
  assert.ok(!m.outbox().join('').includes('t_secretline') && !m.outbox().join('').includes('lines'));
  assert.ok(!JSON.stringify(m.logs).includes('@'));
});

test('budget: owner kinds are not reserved and are refused before invite and password-reset under pressure', (t) => {
  const reserve = createMailBudget({ directory: temporary(t), mailbox: 'mail.example.test:u', maxPerHour: 20 });
  for (let i = 0; i < 18; i++) assert.equal(reserve(`u${i}@example.test`, 'verify-email'), null);
  assert.equal(reserve(OWNER, 'owner-event'), 'rate_cap');
  assert.equal(reserve(OWNER, 'owner-digest'), 'rate_cap');
  assert.equal(reserve('invited@example.test', 'invite'), null);
  assert.equal(reserve('reset@example.test', 'password-reset'), null);
  assert.equal(reserve('late@example.test', 'invite'), 'rate_cap');
});

test('budget: owner kinds stop at 80% of the hour so verification mail keeps capacity', (t) => {
  const reserve = createMailBudget({ directory: temporary(t), mailbox: 'mail.example.test:u', maxPerHour: 20 });
  for (let i = 0; i < 15; i++) assert.equal(reserve(`u${i}@example.test`, 'verify-email'), null);
  assert.equal(reserve(OWNER, 'owner-event'), null, 'below 80% an owner notice is allowed');
  assert.equal(reserve(OWNER, 'owner-digest'), 'rate_cap', 'at 80% owner kinds are refused');
  assert.equal(reserve('u16@example.test', 'verify-email'), null, 'verification still goes through');
  assert.equal(reserve('u17@example.test', 'verify-email'), null);
});

test('file mailer writes only to, kind and status for owner kinds', async (t) => {
  const outboxDir = temporary(t);
  await createFileMailer({ outboxDir }).send({ to: OWNER, kind: 'owner-event', lines: ['tenant t_secretline'], link: 'x' });
  const [name] = readdirSync(outboxDir).filter((item) => item.endsWith('.json'));
  assert.deepEqual(JSON.parse(readFileSync(join(outboxDir, name), 'utf8')), { to: OWNER, kind: 'owner-event' });
});

// ---- Hooks ----

function recorder() {
  const events = [];
  return { events, notify(event) { events.push(event); }, flush: async () => {}, stop() {} };
}
async function portal(t, config = {}) {
  const owner = recorder();
  const f = await fixture(t, { openSignup: true, signupIpPerHour: 100, logger: () => {}, ...config }, { ownerNotify: owner });
  const signupCall = (email, extra = {}) => f.client.call('/api/signup', 'POST', { email, password: fakeSecret(), accept_terms: true, ...extra });
  return { ...f, owner, signupCall, accounts: () => f.store.read('accounts', emptyAccounts()) };
}

test('sign-up: open, invite and reclaim each notify once; refused, existing, invalid and no-terms never do', async (t) => {
  const f = await portal(t, { signupDisposable: new Set(['blocked.example.test']) });
  for (const [email, extra] of [['a@blocked.example.test', {}], ['not-an-email', {}], ['terms@example.test', { accept_terms: false }],
    ['short@example.test', { password: 'x' }]]) {
    assert.deepEqual((await f.signupCall(email, extra)).data, { ok: true });
  }
  assert.deepEqual(f.owner.events, []);
  await f.signupCall('open@example.test');
  const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email: 'invited@example.test' });
  await f.signupCall('invited@example.test', { invite_code: code });
  await f.signupCall('wrong@example.test', { invite_code: fakeSecret() });
  await f.signupCall('open@example.test');
  const { users } = f.accounts();
  assert.deepEqual(f.owner.events, [
    { type: 'signup', source: 'open', tenant_id: users[0].tenant_id, user_id: users[0].id, email: 'open@example.test' },
    { type: 'signup', source: 'invite', tenant_id: users[1].tenant_id, user_id: users[1].id, email: 'invited@example.test' }]);
  f.advance(3600001);
  await f.client.call('/api/me');
  await f.signupCall('open@example.test');
  assert.deepEqual(f.owner.events.slice(2), [{ type: 'signup', source: 'open', reclaimed: true, tenant_id: users[0].tenant_id, user_id: users[0].id, email: 'open@example.test' }]);
  // Invite-only mode never notifies for an uninvited address.
  const g = await portal(t, { openSignup: false });
  await g.signupCall('uninvited@example.test');
  assert.deepEqual(g.owner.events, []);
});

test('a throwing notifier or a failing owner mailer leaves the generic response and account state unchanged', async (t) => {
  const outcomes = [];
  for (const ownerNotify of [null, { notify() { throw new Error('boom'); } },
    createOwnerNotify({ to: OWNER, store: createStore(temporary(t)), mailer: { send() { throw new Error('boom'); } } }),
    createOwnerNotify({ to: OWNER, store: createStore(temporary(t)), mailer: { enqueue: async () => { throw new Error('boom'); } } })]) {
    const f = await fixture(t, { openSignup: true, logger: () => {} }, ownerNotify ? { ownerNotify } : {});
    const response = await f.client.call('/api/signup', 'POST', { email: 'new@example.test', password: fakeSecret(), accept_terms: true });
    await tick(); await tick();
    const verify = await f.client.call('/api/verify-email', 'POST', { token: linkToken(f.messages[0]), password: fakeSecret() });
    await tick();
    const { users, tenants } = f.store.read('accounts', emptyAccounts());
    outcomes.push({ status: response.status, data: response.data, verify: verify.status, users: users.length, tenants: tenants.length,
      verified: Boolean(users[0].email_verified_at), mails: f.messages.map((m) => m.kind) });
    ownerNotify?.stop?.();
  }
  for (const outcome of outcomes) assert.deepEqual(outcome, outcomes[0]);
  assert.deepEqual(outcomes[0], { status: 200, data: { ok: true }, verify: 200, users: 1, tenants: 1, verified: true, mails: ['verify-email'] });
});

test('verify notifies only on the first verification, not for a later link', async (t) => {
  const f = await portal(t, { openSignup: false });
  const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email: 'invited@example.test' });
  await f.signupCall('invited@example.test', { invite_code: code });
  f.owner.events.length = 0;
  assert.equal((await f.client.call('/api/verify-email', 'POST', { token: fakeSecret() })).status, 401);
  assert.equal((await f.client.call('/api/verify-email', 'POST', { token: linkToken(f.messages[0]) })).status, 200);
  const user = f.accounts().users[0];
  assert.deepEqual(f.owner.events, [{ type: 'verify', tenant_id: user.tenant_id, user_id: user.id, email: 'invited@example.test' }]);
  // A fresh verify link for an already verified user does not notify again.
  const raw = fakeSecret();
  const data = f.accounts();
  data.links.push({ token_hash: digest(raw), user_id: user.id, kind: 'verify-email', expires_at: f.now() + 3600000 });
  f.store.write('accounts', data);
  assert.equal((await f.client.call('/api/verify-email', 'POST', { token: raw })).status, 200);
  assert.equal(f.owner.events.length, 1);
});

test('trial sweep: a new pause notifies once with the first user; reassert, edge failure and unpause do not', async (t) => {
  const store = createStore(temporary(t));
  const startAt = Date.parse('2026-10-01T09:30:00.000Z');
  const tenant = (id) => ({ id, name: '', plan: 'trial', hostname_limit: 1, status: 'active', source: 'open', created_at: new Date(startAt).toISOString() });
  store.write('accounts', { ...emptyAccounts(), tenants: [tenant(tids[0]), tenant(tids[1])],
    users: [{ id: 'user-0', tenant_id: tids[0], email: 'user0@example.com' }] });
  const events = [];
  let down = new Set([tids[1]]);
  const edge = { async pauseTenant(tid) { if (down.has(tid)) throw new Error('edge down'); return {}; }, async unpauseTenant() { return {}; } };
  const sweep = (at, notify = (event) => events.push(event)) => sweepTrials({ store, edge, now: () => at, notify });
  await sweep(startAt + 8 * DAY);
  assert.deepEqual(events, [{ type: 'trial_pause', tenant_id: tids[0], paused_at: new Date(startAt + 8 * DAY).toISOString(), email: 'user0@example.com' }]);
  await sweep(startAt + 9 * DAY);
  assert.equal(events.length, 1, 'reassert and edge failure do not notify');
  down = new Set();
  await sweep(startAt + 10 * DAY);
  assert.deepEqual(events.slice(1), [{ type: 'trial_pause', tenant_id: tids[1], paused_at: new Date(startAt + 10 * DAY).toISOString() }]);
  store.write('trial_overrides', { tenants: { [tids[0]]: { plan: 'pro' } } });
  assert.deepEqual(await sweep(startAt + 11 * DAY), { paused: 0, unpaused: 1, failed: 0 });
  assert.equal(events.length, 2);
  // A throwing notifier cannot turn a pause into a failure.
  store.write('trial_overrides', { tenants: {} });
  assert.deepEqual(await sweep(startAt + 12 * DAY, () => { throw new Error('boom'); }), { paused: 1, unpaused: 0, failed: 0 });
});

async function freePort() {
  const probe = createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

test('server: OWNER_NOTIFY_* unset behaves as before; set, owner mail reaches the outbox without its lines', async (t) => {
  const lines = [];
  t.mock.method(console, 'log', (line) => lines.push(line));
  const boot = async (extra) => {
    const dataDir = temporary(t);
    const port = await freePort();
    const app = start({ STATE_DIRECTORY: dataDir, PORTAL_ORIGIN: origin, PORTAL_KEY: fakeSecret(), PORTAL_PORT: String(port), OPEN_SIGNUP: '1', ...extra });
    await once(app, 'listening');
    const client = browser(port);
    await client.call('/api/me');
    const result = await client.call('/api/signup', 'POST', { email: 'new@example.test', password: fakeSecret(), accept_terms: true });
    await tick(); await tick();
    await new Promise((resolve) => { app.close(resolve); app.closeAllConnections(); });
    await tick(); await tick();
    const outbox = readdirSync(join(dataDir, 'outbox')).filter((name) => name.endsWith('.json'))
      .map((name) => JSON.parse(readFileSync(join(dataDir, 'outbox', name), 'utf8')));
    return { result, outbox, state: existsSync(join(dataDir, 'owner_notify.json')) };
  };
  const off = await boot({});
  assert.deepEqual(off.result.data, { ok: true });
  assert.deepEqual(off.outbox.map((m) => m.kind), ['verify-email']);
  assert.equal(off.state, false);
  assert.ok(!lines.some((line) => line.includes('owner_notify')));
  const on = await boot({ OWNER_NOTIFY_EMAIL: OWNER });
  assert.deepEqual(on.result.data, { ok: true });
  assert.deepEqual(on.outbox.filter((m) => m.kind === 'owner-event'), [{ to: OWNER, kind: 'owner-event' }]);
  assert.equal(on.state, true);
  const invalid = await boot({ OWNER_NOTIFY_EMAIL: 'nope' });
  assert.deepEqual(invalid.outbox.map((m) => m.kind), ['verify-email']);
  assert.equal(lines.filter((line) => line.includes('"invalid_address"')).length, 1);
  const owned = lines.filter((line) => line.includes('owner_notify'));
  assert.ok(owned.length > 0 && owned.every((line) => !line.includes('@')));
});

test('owner_notify logs never contain an address', () => {
  assert.ok(allLogs.length > 0);
  assert.ok(allLogs.every((entry) => entry.event === 'owner_notify' && !JSON.stringify(entry).includes('@')));
});
