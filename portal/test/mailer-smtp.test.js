import { createAuth } from '../src/auth.js';
import { createMailBudget } from '../src/mail-budget.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import { once } from 'node:events';
import { readFileSync, readdirSync, statSync, writeFileSync, utimesSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { createSmtpMailer, buildMessage, smtpDeliver } from '../src/mailer-smtp.js';
import { createFileMailer, purgeOutbox, scheduleOutboxPurge } from '../src/mailer-file.js';
import { renderMail, mailKinds } from '../src/mail-templates.js';
import { selectMailer } from '../server.js';
import { temporary, fakeSecret } from './helpers.js';

// Throwaway self-signed localhost pair generated per run; nothing key-like is committed.
function throwawayCert() {
  const dir = mkdtempSync(join(tmpdir(), 'smtp-test-tls-'));
  const key = join(dir, 'key.pem'), cert = join(dir, 'cert.pem');
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-keyout', key, '-out', cert], { stdio: 'ignore' });
    return { key: readFileSync(key), cert: readFileSync(cert) };
  } catch { return {}; } finally { rmSync(dir, { recursive: true, force: true }); }
}
const { key, cert } = throwawayCert();
const needsTls = { skip: cert ? false : 'openssl unavailable: cannot generate a throwaway TLS certificate for STARTTLS tests' };
const tlsOptions = { ca: cert, servername: 'localhost' };

// In-process fake submission server on 127.0.0.1. `stall` names a verb (or 'greeting') that never gets a reply.
async function fakeSmtp(t, { startTls = true, authOk = true, stall } = {}) {
  const state = { connections: 0, commands: [], auth: [], messages: [] };
  const sockets = new Set();
  const server = net.createServer((raw) => {
    state.connections++;
    sockets.add(raw);
    let socket = raw, secure = false, buffer = '', inData = false, data = '';
    const write = (line) => socket.write(`${line}\r\n`);
    const onData = (chunk) => {
      buffer += chunk.toString('utf8');
      let index;
      while ((index = buffer.indexOf('\r\n')) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        if (inData) {
          if (line === '.') { inData = false; state.messages.push(data); data = ''; if (stall !== 'message') write('250 2.0.0 queued'); }
          else data += `${line}\r\n`;
          continue;
        }
        const verb = line.split(' ')[0].toUpperCase();
        state.commands.push(verb === 'AUTH' ? 'AUTH' : line);
        if (stall === verb) continue;
        if (verb === 'EHLO') {
          const ext = [...(startTls && !secure ? ['STARTTLS'] : []), ...(secure ? ['AUTH PLAIN LOGIN'] : []), 'SIZE 1000000'];
          write(`250-fake.example.test`);
          ext.forEach((item, i) => write(`250${i === ext.length - 1 ? ' ' : '-'}${item}`));
        } else if (verb === 'STARTTLS') {
          write('220 2.0.0 ready');
          raw.off('data', onData);
          socket = new tls.TLSSocket(raw, { isServer: true, key, cert });
          socket.on('data', onData).on('error', () => {});
          secure = true;
          return;
        } else if (verb === 'AUTH') {
          const [, user, pass] = Buffer.from(line.split(' ')[2], 'base64').toString().split('\0');
          state.auth.push({ user, pass, secure });
          write(authOk ? '235 2.7.0 ok' : '535 5.7.8 bad credentials');
        } else if (verb === 'DATA') { inData = true; write('354 go'); }
        else if (verb === 'QUIT') { write('221 bye'); socket.end(); }
        else write('250 ok');
      }
    };
    raw.on('data', onData).on('error', () => {});
    if (stall !== 'greeting') write('220 fake.example.test ESMTP');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => { for (const socket of sockets) socket.destroy(); server.close(resolve); }));
  return { port: server.address().port, state };
}

function mailer(t, port, overrides = {}) {
  const outboxDir = temporary(t);
  const logs = [];
  const pass = fakeSecret();
  const instance = createSmtpMailer({ host: '127.0.0.1', port, user: 'noreply@example.invalid', pass, from: 'noreply@example.invalid',
    replyTo: 'support@example.invalid', fallback: createFileMailer({ outboxDir }), logger: (entry) => logs.push(entry), tlsOptions, timeoutMs: 1000, ...overrides });
  const outbox = () => readdirSync(outboxDir).filter((name) => name.endsWith('.json')).map((name) => {
    assert.equal(statSync(join(outboxDir, name)).mode & 0o777, 0o600);
    return JSON.parse(readFileSync(join(outboxDir, name), 'utf8'));
  });
  return { instance, logs, pass, outbox, outboxDir };
}
const verifyLink = () => `https://portal.example.test/verify-email#token=${fakeSecret()}`;
const noSecrets = (logs, ...secrets) => {
  const text = JSON.stringify(logs);
  for (const secret of secrets) assert.ok(!text.includes(secret), 'log leaked a secret or address');
};

test('happy path: STARTTLS before AUTH PLAIN, full headers, redacted outbox audit copy', needsTls, async (t) => {
  const smtp = await fakeSmtp(t);
  const m = mailer(t, smtp.port);
  const link = verifyLink();
  assert.deepEqual(await m.instance.send({ to: 'new@example.test', kind: 'verify-email', link }), { delivered: 'smtp' });
  assert.deepEqual(smtp.state.commands.slice(0, 7), ['EHLO example.invalid', 'STARTTLS', 'EHLO example.invalid', 'AUTH',
    'MAIL FROM:<noreply@example.invalid>', 'RCPT TO:<new@example.test>', 'DATA']);
  assert.deepEqual(smtp.state.auth, [{ user: 'noreply@example.invalid', pass: m.pass, secure: true }]);
  const [message] = smtp.state.messages;
  for (const header of ['From: noreply@example.invalid', 'To: new@example.test', 'Reply-To: support@example.invalid',
    `Subject: ${renderMail({ kind: 'verify-email', link }).subject}`, 'MIME-Version: 1.0']) assert.ok(message.includes(`${header}\r\n`), header);
  assert.match(message, /\r\nDate: [A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT\r\n/);
  assert.match(message, /\r\nMessage-ID: <[0-9a-f-]{36}@example\.invalid>\r\n/);
  assert.ok(message.includes(link));
  assert.deepEqual(m.outbox(), [{ to: 'new@example.test', kind: 'verify-email', link: '[redacted]', status: 'sent' }]);
  assert.deepEqual(m.logs, [{ event: 'mail', kind: 'verify-email', result: 'sent' }]);
  noSecrets(m.logs, link, m.pass, 'new@example.test');
});

test('refuses to authenticate when STARTTLS is not offered and falls back to the outbox', async (t) => {
  const smtp = await fakeSmtp(t, { startTls: false });
  const m = mailer(t, smtp.port);
  const link = verifyLink();
  assert.deepEqual(await m.instance.send({ to: 'new@example.test', kind: 'password-reset', link }), { delivered: 'failed', reason: 'starttls_unavailable' });
  assert.deepEqual(smtp.state.auth, []);
  assert.ok(!smtp.state.commands.some((line) => /^(AUTH|MAIL|RCPT)/.test(line)));
  assert.deepEqual(m.outbox(), [{ to: 'new@example.test', kind: 'password-reset', link: '[redacted]', status: 'failed:starttls_unavailable' }]);
  assert.deepEqual(m.logs, [{ event: 'mail', kind: 'password-reset', result: 'fallback', reason: 'starttls_unavailable' }]);
  noSecrets(m.logs, link, m.pass, 'new@example.test');
});

test('an untrusted or mismatched STARTTLS certificate is refused before AUTH', needsTls, async (t) => {
  for (const options of [{}, { ca: cert, servername: 'other.example.test' }]) {
    const smtp = await fakeSmtp(t);
    const m = mailer(t, smtp.port, { tlsOptions: options });
    assert.equal((await m.instance.send({ to: 'new@example.test', kind: 'verify-email', link: verifyLink() })).reason, 'tls');
    assert.deepEqual(smtp.state.auth, []);
  }
});

test('authentication failure stops before MAIL FROM and saves a redacted audit', needsTls, async (t) => {
  const smtp = await fakeSmtp(t, { authOk: false });
  const m = mailer(t, smtp.port);
  const link = verifyLink();
  assert.equal((await m.instance.send({ to: 'new@example.test', kind: 'verify-email', link })).reason, 'auth_failed');
  assert.ok(!smtp.state.commands.some((line) => line.startsWith('MAIL')));
  assert.equal(m.outbox()[0].link, '[redacted]');
  noSecrets(m.logs, link, m.pass, 'new@example.test');
});

test('timeouts on a silent greeting or an unanswered DATA terminator fall back without throwing', needsTls, async (t) => {
  for (const stall of ['greeting', 'message']) {
    const smtp = await fakeSmtp(t, { stall });
    const m = mailer(t, smtp.port, { timeoutMs: 150 });
    const started = Date.now();
    assert.equal((await m.instance.send({ to: 'new@example.test', kind: 'verify-email', link: verifyLink() })).reason, 'timeout');
    assert.ok(Date.now() - started < 2000);
    assert.equal(m.outbox().length, 1);
  }
});

test('header and command injection is rejected before any connection', async (t) => {
  const smtp = await fakeSmtp(t);
  const m = mailer(t, smtp.port);
  for (const [to, link, reason] of [
    ['new@example.test\r\nBcc: other@example.test', verifyLink(), 'invalid_address'],
    ['new@example.test>\r\nRCPT TO:<other@example.test', verifyLink(), 'invalid_address'],
    ['new@example.test\nX: y', verifyLink(), 'invalid_address'],
    ['new@example.test', `${verifyLink()}\r\n.\r\nMAIL FROM:<x@example.test>`, 'invalid_message'],
    ['new@example.test', `${verifyLink()}\nBcc: other@example.test`, 'invalid_message'],
  ]) assert.equal((await m.instance.send({ to, kind: 'verify-email', link })).reason, reason);
  assert.equal((await m.instance.send({ to: 'new@example.test', kind: 'bogus\r\nBcc: x', link: verifyLink() })).reason, 'invalid_message');
  assert.equal(smtp.state.connections, 0);
  const base = { from: 'a@example.test', to: 'b@example.test', subject: 'Hi', text: 'x', date: 'now', messageId: '<1@example.test>' };
  for (const field of ['from', 'to', 'replyTo', 'subject', 'messageId']) {
    assert.throws(() => buildMessage({ ...base, [field]: 'ok\r\nBcc: other@example.test' }), { reason: 'invalid_message' });
  }
  assert.throws(() => buildMessage({ ...base, text: 'a\r\n.\r\nQUIT' }), { reason: 'invalid_message' });
  for (const bad of [{ from: 'x@example.test\r\nBcc: y@example.test' }, { replyTo: 'y\n@example.test' }, { user: 'u\r\nRSET' }, { pass: 'p\r\nQUIT' }, { host: 'mail.example.test\r\n' }]) {
    assert.throws(() => createSmtpMailer({ host: '127.0.0.1', user: 'u', pass: 'p', from: 'x@example.test', fallback: {}, ...bad }), /^Error: Invalid mail configuration$/);
  }
});

test('message body is dot-stuffed and terminated once', needsTls, async (t) => {
  const smtp = await fakeSmtp(t);
  const message = buildMessage({ from: 'a@example.test', to: 'b@example.test', subject: 'Hi', text: 'one\n.\n..two\nend',
    date: new Date(0).toUTCString(), messageId: '<1@example.test>' });
  assert.ok(message.endsWith('\r\n\r\none\r\n..\r\n...two\r\nend\r\n'));
  await smtpDeliver({ host: '127.0.0.1', port: smtp.port, user: 'u', pass: 'p', from: 'a@example.test', to: 'b@example.test', message, tlsOptions, timeoutMs: 1000 });
  assert.ok(smtp.state.messages[0].endsWith('\r\none\r\n..\r\n...two\r\nend\r\n'));
  assert.equal(smtp.state.messages.length, 1);
});

test('persistent hourly cap records failure and recovers after the window', needsTls, async (t) => {
  const smtp = await fakeSmtp(t);
  let clock = Date.UTC(2026, 0, 1);
  const m = mailer(t, smtp.port, { maxPerHour: 2, now: () => clock });
  const results = [];
  for (let i = 0; i < 3; i++) results.push(await m.instance.send({ to: `u${i}@example.test`, kind: 'verify-email', link: verifyLink() }));
  assert.deepEqual(results.map((r) => r.delivered), ['smtp', 'smtp', 'failed']);
  assert.equal(results[2].reason, 'rate_cap');
  assert.equal(smtp.state.messages.length, 2);
  clock += 3600000;
  assert.equal((await m.instance.send({ to: 'later@example.test', kind: 'verify-email', link: verifyLink() })).delivered, 'smtp');
});

test('unreachable server and a failing outbox never throw to the caller', async (t) => {
  const closed = net.createServer();
  closed.listen(0, '127.0.0.1');
  await once(closed, 'listening');
  const { port } = closed.address();
  await new Promise((resolve) => closed.close(resolve));
  const m = mailer(t, port);
  const link = verifyLink();
  assert.deepEqual(await m.instance.send({ to: 'new@example.test', kind: 'verify-email', link }), { delivered: 'failed', reason: 'connect' });
  assert.equal(m.outbox()[0].link, '[redacted]');
  const logs = [];
  const broken = createSmtpMailer({ host: '127.0.0.1', port, user: 'u', pass: 'p', from: 'noreply@example.invalid', logger: (e) => logs.push(e),
    fallback: { async send() { throw new Error('disk full'); } } });
  assert.equal((await broken.send({ to: 'new@example.test', kind: 'verify-email', link })).delivered, 'failed');
  assert.deepEqual(logs.map((e) => e.reason), ['connect', 'outbox_write_failed']);
  noSecrets([...m.logs, ...logs], link, 'new@example.test');
});

test('transport selection defaults to file and rejects invalid smtp settings without echoing values', async (t) => {
  const outboxDir = temporary(t);
  const link = verifyLink();
  assert.equal((await selectMailer({}, { outboxDir }).send({ to: 'new@example.test', kind: 'verify-email', link })).delivered, 'outbox');
  assert.equal(JSON.parse(readFileSync(join(outboxDir, readdirSync(outboxDir)[0]), 'utf8')).link, link);
  const pass = fakeSecret();
  const good = { MAIL_TRANSPORT: 'smtp', SMTP_HOST: 'mail.example.test', SMTP_USER: 'noreply@example.invalid', SMTP_PASS: pass };
  assert.equal(typeof selectMailer(good, { outboxDir }).send, 'function');
  for (const env of [{ MAIL_TRANSPORT: 'sendmail' }, { ...good, SMTP_HOST: '' }, { ...good, SMTP_PASS: '' }, { ...good, SMTP_USER: undefined },
    { ...good, SMTP_PORT: 'abc' }, { ...good, SMTP_PORT: '70000' }, { ...good, MAIL_FROM: `bad\r\n${pass}@example.test` },
    { ...good, MAIL_REPLY_TO: 'nope' }, { ...good, MAIL_MAX_PER_HOUR: '0' }, { ...good, SMTP_HOST: `bad host ${pass}` }]) {
    assert.throws(() => selectMailer(env, { outboxDir }), (error) => error.message === 'Invalid mail configuration' && !error.message.includes(pass));
  }
});

test('smtp transport via selectMailer uses PORTAL_SUPPORT_EMAIL as Reply-To and the documented From fallback', needsTls, async (t) => {
  const smtp = await fakeSmtp(t);
  const outboxDir = temporary(t);
  const mail = selectMailer({ MAIL_TRANSPORT: 'smtp', SMTP_HOST: '127.0.0.1', SMTP_PORT: String(smtp.port), SMTP_USER: 'u', SMTP_PASS: fakeSecret(),
    PORTAL_SUPPORT_EMAIL: 'help@example.test' }, { outboxDir, logger: () => {}, tlsOptions });
  assert.equal((await mail.send({ to: 'new@example.test', kind: 'verify-email', link: verifyLink() })).delivered, 'smtp');
  assert.ok(smtp.state.messages[0].includes('From: noreply@example.invalid\r\n'));
  assert.ok(smtp.state.messages[0].includes('Reply-To: help@example.test\r\n'));
});

test('templates cover every kind with fixed subjects and plain text', () => {
  assert.deepEqual(mailKinds, ['verify-email', 'password-reset', 'invite', 'domain-request']);
  for (const kind of mailKinds) {
    const link = `https://portal.example.test/${kind}`;
    const { subject, text } = renderMail({ kind, link, code: 'invite-code-123' });
    assert.match(subject, /^[\x20-\x7e]+$/);
    assert.equal(renderMail({ kind, link: 'https://portal.example.test/other', code: 'x' }).subject, subject);
    assert.ok(text.includes(link));
    assert.ok(!/<[a-z]/i.test(text));
  }
  assert.match(renderMail({ kind: 'invite', link: 'https://portal.example.test/signup', code: 'invite-code-123' }).text, /Invite code: invite-code-123/);
  assert.throws(() => renderMail({ kind: 'invite', link: 'https://portal.example.test/signup' }));
  assert.throws(() => renderMail({ kind: 'unknown', link: 'x' }));
});

test('outbox TTL purge removes only regular message files older than seven days', (t) => {
  const outboxDir = temporary(t);
  const now = Date.now();
  for (const [name, age] of [['old.json', 8], ['fresh.json', 6], ['old.txt', 30]]) {
    writeFileSync(join(outboxDir, name), '{}\n');
    utimesSync(join(outboxDir, name), (now - age * 86400000) / 1000, (now - age * 86400000) / 1000);
  }
  assert.equal(purgeOutbox(outboxDir, now), 1);
  assert.deepEqual(readdirSync(outboxDir).sort(), ['fresh.json', 'old.txt']);
  assert.equal(purgeOutbox(join(outboxDir, 'missing'), now), 0);
});


test('shared persistent budget limits recipients and reserves priority capacity across instances', async (t) => {
  const outboxDir = temporary(t);
  let clock = Date.now(), delivered = 0;
  const make = () => createSmtpMailer({ host: 'mail.example.test', user: 'u', pass: 'p', from: 'noreply@example.invalid',
    fallback: createFileMailer({ outboxDir }), maxPerHour: 10, now: () => clock, deliver: async () => { delivered++; } });
  const send = (to, kind = 'verify-email') => make().send({ to, kind, link: verifyLink(), code: kind === 'invite' ? fakeSecret() : undefined });
  const results = await Promise.all(Array.from({ length: 4 }, () => send('same@example.test')));
  assert.equal(results.filter((r) => r.delivered === 'smtp').length, 3);
  assert.equal(results[3].reason, 'recipient_cap');
  for (let i = 0; i < 6; i++) assert.equal((await send(`u${i}@example.test`)).delivered, 'smtp');
  assert.equal((await send('overflow@example.test')).reason, 'rate_cap');
  assert.equal((await send('priority@example.test', 'invite')).delivered, 'smtp');
  assert.equal((await send('reset@example.test', 'password-reset')).reason, 'rate_cap');
  assert.equal(delivered, 10);
  clock += 3600000;
  assert.equal((await send('same@example.test')).delivered, 'smtp');
});

test('SMTP failure never persists invite codes or links, even when outbox fails', async (t) => {
  const outboxDir = temporary(t), code = fakeSecret(), link = verifyLink();
  const fallback = createFileMailer({ outboxDir, maxFiles: 1 });
  const mail = createSmtpMailer({ host: 'mail.example.test', user: 'u', pass: 'p', from: 'noreply@example.invalid', fallback,
    deliver: async () => { throw new Error('unavailable'); } });
  assert.equal((await mail.send({ to: 'u@example.test', kind: 'invite', link, code })).delivered, 'failed');
  const saved = readFileSync(join(outboxDir, readdirSync(outboxDir).find((name) => name.endsWith('.json'))), 'utf8');
  assert.ok(!saved.includes(code) && !saved.includes(link));
  assert.equal((await mail.send({ to: 'v@example.test', kind: 'invite', link, code })).reason, 'outbox_write_failed');
});

test('periodic purge is hourly, unreferenced, and expires files created after startup', (t) => {
  const dir = temporary(t);
  let tick, unref = false;
  scheduleOutboxPurge(dir, (callback, delay) => { tick = callback; assert.equal(delay, 3600000); return { unref() { unref = true; } }; });
  assert.ok(unref);
  const file = join(dir, 'expired.json');
  writeFileSync(file, '{}');
  utimesSync(file, 0, 0);
  tick();
  assert.deepEqual(readdirSync(dir), []);
});


test('reset handler returns generic responses before queued SMTP finishes', { timeout: 2000 }, async (t) => {
  let release, started = false;
  const pending = new Promise((resolve) => { release = resolve; });
  const mail = mailer(t, 2525, { deliver: async () => { started = true; await pending; } }).instance;
  // Reset requires a tenant that is not suspended (a user without one fails closed).
  const data = { tenants: [{ id: 't_aaaaaaaaaaaaaaaaaaaa', status: 'active' }],
    users: [{ id: 'user-1', tenant_id: 't_aaaaaaaaaaaaaaaaaaaa', email: 'known@example.test' }], links: [] };
  const auth = createAuth({ store: { read: (name, fallback) => (name === 'accounts' ? data : fallback), write() {} }, limits: { take() {} }, now: Date.now,
    mailer: mail, config: { origin: 'https://portal.example.test' } });
  const context = { ip: '127.0.0.1', send: (status, body) => ({ status, body }) };
  try {
    const known = await auth.handle('/api/password-reset', { email: 'known@example.test' }, context);
    await new Promise((resolve) => setImmediate(resolve));
    assert.ok(started);
    const unknown = await auth.handle('/api/password-reset', { email: 'unknown@example.test' }, context);
    assert.deepEqual(known, { status: 200, body: { ok: true } });
    assert.deepEqual(unknown, known);
  } finally { release(); await new Promise((resolve) => setImmediate(resolve)); }
});

test('budget contention and damaged state fail closed without resetting reservations', (t) => {
  const directory = temporary(t);
  const reserve = createMailBudget({ directory, mailbox: 'mail.example.test:u', maxPerHour: 1 });
  assert.equal(reserve('u@example.test', 'invite'), null);
  const file = join(directory, readdirSync(directory)[0]);
  mkdirSync(`${file}.lock`);
  assert.equal(reserve('v@example.test', 'invite'), 'budget_unavailable');
  rmSync(`${file}.lock`, { recursive: true });
  assert.equal(reserve('v@example.test', 'invite'), 'rate_cap');
  writeFileSync(file, '[{}]');
  assert.equal(reserve('v@example.test', 'invite'), 'budget_unavailable');
});

test('crash-left budget and outbox locks are broken after 30 s and logged as lock_stuck', async (t) => {
  const outboxDir = temporary(t), logs = [], old = new Date(Date.now() - 31000);
  const fallback = createFileMailer({ outboxDir, logger: (entry) => logs.push(entry) });
  const m = createSmtpMailer({ host: 'mail.example.test', user: 'u', pass: 'p', from: 'noreply@example.invalid',
    fallback, logger: (entry) => logs.push(entry), deliver: async () => {} });
  const budgetDir = join(outboxDir, '.budget'), link = 'https://portal.example.test/login';
  assert.deepEqual(await m.send({ to: 'a@example.test', kind: 'password-reset', link }), { delivered: 'smtp' });
  const budgetLock = join(budgetDir, `${readdirSync(budgetDir).find((name) => name.endsWith('.json'))}.lock`);
  mkdirSync(budgetLock);
  assert.equal((await m.send({ to: 'b@example.test', kind: 'password-reset', link })).reason, 'budget_unavailable');
  assert.ok(!logs.some((entry) => entry.reason === 'lock_stuck'));
  utimesSync(budgetLock, old, old);
  assert.deepEqual(await m.send({ to: 'b@example.test', kind: 'password-reset', link }), { delivered: 'smtp' });
  assert.deepEqual(logs.filter((entry) => entry.reason === 'lock_stuck'), [{ event: 'mail', kind: 'mail', result: 'lock_broken', reason: 'lock_stuck' }]);
  const writeLock = join(outboxDir, '.write-lock');
  mkdirSync(writeLock);
  await assert.rejects(fallback.send({ to: 'c@example.test', kind: 'password-reset', link }), /Outbox locked/);
  utimesSync(writeLock, old, old);
  assert.deepEqual(await fallback.send({ to: 'c@example.test', kind: 'password-reset', link }), { delivered: 'outbox' });
  assert.equal(logs.filter((entry) => entry.reason === 'lock_stuck').length, 2);
  assert.deepEqual(readdirSync(outboxDir).filter((name) => !name.endsWith('.json')), ['.budget']);
});

test('SMTP envelope and headers support atext and normalize IDN domains', needsTls, async (t) => {
  const smtp = await fakeSmtp(t);
  const m = mailer(t, smtp.port);
  for (const [to, expected] of [["owner'tag+=_-@example.test", "owner'tag+=_-@example.test"],
    ['owner@bücher.example.test', 'owner@xn--bcher-kva.example.test']]) {
    for (const kind of ['verify-email', 'password-reset']) {
      assert.equal((await m.instance.send({ to, kind, link: verifyLink() })).delivered, 'smtp');
      assert.ok(smtp.state.commands.includes('RCPT TO:<' + expected + '>'));
      assert.ok(smtp.state.messages.at(-1).includes('To: ' + expected + '\r\n'));
    }
  }
});
