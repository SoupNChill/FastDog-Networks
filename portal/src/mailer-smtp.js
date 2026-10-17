// Minimal SMTP submission client (RFC 5321/3207/4616): STARTTLS required, AUTH PLAIN, one message per connection.
// Failures and the local hourly cap fall back to the file outbox; send() never throws and logs reason codes only.
import net from 'node:net';
import tls from 'node:tls';
import { randomUUID } from 'node:crypto';
import { renderMail } from './mail-templates.js';

const ADDRESS = /^[A-Za-z0-9._+-]{1,64}@(?=.{1,190}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$/;
const HOST = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/;
export const isAddress = (value) => typeof value === 'string' && ADDRESS.test(value);
export const isMailHost = (value) => typeof value === 'string' && (HOST.test(value) || net.isIP(value) > 0);
class SmtpError extends Error { constructor(reason) { super(`smtp ${reason}`); this.reason = reason; } }
const failure = (reason) => new SmtpError(reason);
// Header values (and anything echoed into a header or command) must be single-line printable ASCII.
const headerSafe = (value) => typeof value === 'string' && /^[\x20-\x7e]*$/.test(value);

export function buildMessage({ from, to, replyTo, subject, text, date, messageId }) {
  const headers = [['From', from], ['To', to], ...(replyTo ? [['Reply-To', replyTo]] : []), ['Subject', subject],
    ['Date', date], ['Message-ID', messageId], ['MIME-Version', '1.0'], ['Content-Type', 'text/plain; charset=utf-8'],
    ['Content-Transfer-Encoding', '8bit']];
  for (const [, value] of headers) if (!headerSafe(value)) throw failure('invalid_message');
  if (typeof text !== 'string' || /[\0\r]/.test(text)) throw failure('invalid_message');
  // Dot-stuffing (RFC 5321 4.5.2): any body line starting with "." gets an extra ".".
  const body = text.split('\n').map((line) => (line.startsWith('.') ? `.${line}` : line)).join('\r\n');
  return `${headers.map(([name, value]) => `${name}: ${value}`).join('\r\n')}\r\n\r\n${body}\r\n`;
}

// Parses SMTP replies from a socket; next() resolves the next complete (possibly multi-line) reply.
function replyReader(socket, timeoutMs) {
  let buffer = '', lines = [], error = null, waiter = null;
  const ready = [];
  const settle = () => {
    if (!waiter) return;
    const current = waiter;
    if (ready.length) { waiter = null; clearTimeout(current.timer); current.resolve(ready.shift()); }
    else if (error) { waiter = null; clearTimeout(current.timer); current.reject(error); }
  };
  const onData = (chunk) => {
    buffer += chunk.toString('utf8');
    let index;
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index).replace(/\r$/, '');
      buffer = buffer.slice(index + 1);
      const match = /^(\d{3})([ -])(.*)$/.exec(line);
      if (!match) { error ||= failure('protocol'); break; }
      lines.push(match[3]);
      if (match[2] === ' ') { ready.push({ code: Number(match[1]), lines }); lines = []; }
    }
    if (buffer.length > 8192 || ready.length > 8) error ||= failure('protocol');
    settle();
  };
  const onError = () => { error ||= failure('connection'); settle(); };
  const onClose = () => { error ||= failure('connection'); settle(); };
  socket.on('data', onData).on('error', onError).on('close', onClose);
  return {
    next: () => new Promise((resolve, reject) => {
      waiter = { resolve, reject, timer: setTimeout(() => { waiter = null; reject(failure('timeout')); }, timeoutMs) };
      settle();
    }),
    // Data received before a TLS handshake would be read as if it were protected (STARTTLS injection).
    idle: () => buffer.length === 0 && ready.length === 0 && lines.length === 0,
    detach: () => socket.off('data', onData).off('error', onError).off('close', onClose),
  };
}

function waitFor(socket, event, timeoutMs, reason) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { cleanup(); reject(failure('timeout')); }, timeoutMs);
    const done = () => { cleanup(); resolve(); };
    const failed = () => { cleanup(); reject(failure(reason)); };
    const cleanup = () => { clearTimeout(timer); socket.off(event, done).off('error', failed); };
    socket.once(event, done).once('error', failed);
  });
}

// Delivers one message. Throws SmtpError with a reason code; never includes server text or credentials.
export async function smtpDeliver({ host, port, user, pass, from, to, message, heloName = 'localhost', timeoutMs = 10000, tlsOptions = {} }) {
  let socket = net.connect({ host, port });
  socket.on('error', () => {});
  const sockets = [socket];
  try {
    await waitFor(socket, 'connect', timeoutMs, 'connect');
    let reader = replyReader(socket, timeoutMs);
    const command = async (line, expected, reason) => {
      if (line !== null) socket.write(`${line}\r\n`);
      const reply = await reader.next();
      if (!expected.includes(reply.code)) throw failure(reason);
      return reply;
    };
    await command(null, [220], 'greeting');
    const ehlo = await command(`EHLO ${heloName}`, [250], 'ehlo');
    if (!ehlo.lines.slice(1).some((line) => /^STARTTLS\b/i.test(line))) {
      socket.write('QUIT\r\n');
      throw failure('starttls_unavailable');
    }
    await command('STARTTLS', [220], 'starttls');
    if (!reader.idle()) throw failure('protocol');
    reader.detach();
    const plain = socket;
    socket = tls.connect({ socket: plain, servername: net.isIP(host) ? undefined : host, minVersion: 'TLSv1.2', rejectUnauthorized: true, ...tlsOptions });
    socket.on('error', () => {});
    sockets.push(socket);
    await waitFor(socket, 'secureConnect', timeoutMs, 'tls');
    reader = replyReader(socket, timeoutMs);
    const secured = await command(`EHLO ${heloName}`, [250], 'ehlo');
    if (!secured.lines.slice(1).some((line) => /^AUTH\b.*\bPLAIN\b/i.test(line))) throw failure('auth_unavailable');
    await command(`AUTH PLAIN ${Buffer.from(`\0${user}\0${pass}`).toString('base64')}`, [235], 'auth_failed');
    await command(`MAIL FROM:<${from}>`, [250], 'sender_rejected');
    await command(`RCPT TO:<${to}>`, [250, 251], 'recipient_rejected');
    await command('DATA', [354], 'data_rejected');
    await command(`${message}.`, [250], 'message_rejected');
    socket.write('QUIT\r\n');
  } finally {
    for (const item of sockets.reverse()) item.destroy();
  }
}

export function createSmtpMailer({ host, port = 2525, user, pass, from, replyTo, maxPerHour = 300, fallback, logger = () => {},
  now = Date.now, timeoutMs = 10000, tlsOptions, heloName, deliver = smtpDeliver }) {
  if (!isMailHost(host) || !Number.isInteger(port) || port < 1 || port > 65535 || !headerSafe(user) || !user || !headerSafe(pass) || !pass
    || !isAddress(from) || (replyTo && !isAddress(replyTo)) || !Number.isInteger(maxPerHour) || maxPerHour < 1 || !fallback) {
    throw new Error('Invalid mail configuration');
  }
  const domain = from.split('@')[1];
  heloName ||= domain;
  let sent = [];
  const log = (result, kind, reason) => { try { logger({ event: 'mail', kind, result, ...(reason ? { reason } : {}) }); } catch { /* logging must not break mail */ } };
  const toOutbox = async (message, reason) => {
    log('fallback', message.kind, reason);
    try { await fallback.send({ ...message, status: `failed:${reason}` }); } catch { log('lost', message.kind, 'outbox_write_failed'); }
    return { delivered: 'outbox', reason };
  };
  return {
    async send({ to, kind, link, code }) {
      const message = { to, kind, link, code };
      let rendered;
      try {
        if (!isAddress(to)) throw failure('invalid_address');
        if (!headerSafe(link) || (code !== undefined && !headerSafe(code))) throw failure('invalid_message');
        rendered = renderMail({ kind, link, code });
      } catch (error) { return toOutbox(message, error.reason || 'invalid_message'); }
      const current = now();
      sent = sent.filter((at) => current - at < 3600000);
      if (sent.length >= maxPerHour) return toOutbox(message, 'rate_cap');
      sent.push(current);
      try {
        const data = buildMessage({ from, to, replyTo, subject: rendered.subject, text: rendered.text,
          date: new Date(current).toUTCString(), messageId: `<${randomUUID()}@${domain}>` });
        await deliver({ host, port, user, pass, from, to, message: data, heloName, timeoutMs, tlsOptions });
      } catch (error) { return toOutbox(message, error instanceof SmtpError ? error.reason : 'internal'); }
      log('sent', kind);
      // Keep an audit copy without the secret-bearing link or invite code.
      try { await fallback.send({ to, kind, link: '[redacted]', ...(code ? { code: '[redacted]' } : {}), status: 'sent' }); } catch { log('sent', kind, 'outbox_write_failed'); }
      return { delivered: 'smtp' };
    },
  };
}
