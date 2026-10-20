// Owner visibility (default off, fail-open): operator mail on a new sign-up, a first email verification and a
// trial pause, through the portal mailer. notify() is synchronous and never throws, so no API response, timing
// class or stored account state depends on it. owner_notify.json holds dedupe keys (IDs and times only).
// Logs carry reason codes and counts only, never an address.
import { normalizeEmail } from './tokens.js';

export const OWNER_EVENTS = ['signup', 'verify', 'trial_pause'];
const HOUR = 3600000;
const KEEP_MS = 8 * 86400000;
const QUEUE_MAX = 200;
const LINE_MAX = 200;
const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const id = (value) => (typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,80}$/.test(value) ? value : '?');

export function ownerNotifyConfig(env = {}) {
  const integer = (value, fallback, max) => {
    if (typeof value !== 'string' || !/^\d{1,6}$/.test(value.trim())) return fallback;
    const n = Number(value.trim());
    return n < 1 ? fallback : Math.min(n, max);
  };
  const names = typeof env.OWNER_NOTIFY_EVENTS === 'string' && env.OWNER_NOTIFY_EVENTS.trim()
    ? env.OWNER_NOTIFY_EVENTS.split(',').map((name) => name.trim().toLowerCase()) : OWNER_EVENTS;
  return {
    to: typeof env.OWNER_NOTIFY_EMAIL === 'string' && env.OWNER_NOTIFY_EMAIL.trim() ? env.OWNER_NOTIFY_EMAIL.trim() : null,
    events: OWNER_EVENTS.filter((name) => names.includes(name)),
    // mail-budget allows 3 messages per recipient per hour, so more could never be delivered.
    maxPerHour: integer(env.OWNER_NOTIFY_MAX_PER_HOUR, 3, 3),
    batchMs: integer(env.OWNER_NOTIFY_BATCH_MINUTES, 15, 120) * 60000,
    showEmail: env.OWNER_NOTIFY_SHOW_EMAIL === '1',
  };
}

export const maskEmail = (email) => {
  const [local, domain] = String(email).split('@');
  return domain ? `${local.slice(0, 1)}***@${domain}` : '***';
};

let clockFormat;
export function mountain(ms) {
  try {
    clockFormat ||= new Intl.DateTimeFormat('en-US', { timeZone: 'America/Denver', year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
    const p = Object.fromEntries(clockFormat.formatToParts(new Date(ms)).map((part) => [part.type, part.value]));
    return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute} MT`;
  } catch { return `${new Date(ms).toISOString().slice(0, 16).replace('T', ' ')} UTC`; }
}

const noop = Object.freeze({ notify() {}, flush: async () => {}, stop() {} });

export function createOwnerNotify({ mailer, to, store, logger, now = Date.now, events = OWNER_EVENTS, maxPerHour = 3, batchMs = 15 * 60000,
  showEmail = false, schedule = setTimeout, cancel = clearTimeout } = {}) {
  const log = (result, reason, count) => {
    try { logger?.({ event: 'owner_notify', result, ...(reason ? { reason } : {}), ...(count ? { count } : {}) }); } catch { /* Logging cannot affect callers. */ }
  };
  if (to === undefined || to === null || to === '') return noop;
  const address = normalizeEmail(to);
  if (!address) { log('disabled', 'invalid_address'); return noop; }
  if (!mailer || !store) { log('disabled', 'unavailable'); return noop; }
  const wanted = new Set(events);
  const cap = Math.min(Math.max(Number.isInteger(maxPerHour) ? maxPerHour : 3, 1), 3);
  const queue = [];
  let sentTimes = [];
  let timer = null, immediate = null, stopped = false;

  const readSent = () => {
    try {
      const value = store.read('owner_notify', { sent: {} });
      if (plain(value) && plain(value.sent) && Object.values(value.sent).every(Number.isFinite)) return value.sent;
    } catch { /* fall through */ }
    log('fail_open', 'state_unreadable');
    return {};
  };
  const markSent = (keys) => {
    const cutoff = now() - KEEP_MS;
    const sent = Object.fromEntries(Object.entries(readSent()).filter(([, at]) => at >= cutoff));
    for (const key of keys) sent[key] = now();
    try { store.write('owner_notify', { sent }); } catch { log('fail_open', 'state_write_failed'); }
  };
  const who = (email) => (typeof email !== 'string' || !email ? null : showEmail ? email : maskEmail(email));
  const describe = (event, at) => {
    const tenant = id(event.tenant_id);
    if (event.type === 'signup') {
      const source = event.source === 'open' ? 'open' : 'invite';
      return { key: event.reclaimed ? `reclaim:${id(event.user_id)}:${Math.floor(at / 60000)}` : `signup:${tenant}`,
        line: `New sign-up (${source}${event.reclaimed ? ', reclaimed' : ''}): ${who(event.email) ?? '?'} - tenant ${tenant} - ${mountain(at)}` };
    }
    if (event.type === 'verify') {
      return { key: `verify:${id(event.user_id)}`, line: `Email verified: ${who(event.email) ?? '?'} - tenant ${tenant} - ${mountain(at)}` };
    }
    const email = who(event.email);
    const when = typeof event.paused_at === 'string' && event.paused_at ? event.paused_at : new Date(at).toISOString().slice(0, 10);
    return { key: `trial_pause:${tenant}:${when}`, line: `Trial paused: tenant ${tenant}${email ? ` (${email})` : ''} - ${mountain(at)}` };
  };

  const arm = (ms) => {
    cancel(timer);
    timer = schedule(() => { timer = null; deliver(); }, Math.max(0, ms));
    timer?.unref?.();
  };
  // Sends everything queued as one mail when the hourly cap allows; otherwise waits for the next slot.
  function deliver() {
    if (stopped || !queue.length) return Promise.resolve();
    const current = now();
    sentTimes = sentTimes.filter((at) => current - at < HOUR);
    if (sentTimes.length >= cap) { arm(sentTimes[0] + HOUR - current); return Promise.resolve(); }
    const batch = queue.splice(0);
    sentTimes.push(current);
    // Further events in the next window coalesce into one mail at its end.
    arm(batchMs);
    // Marked at hand-off: a failed delivery is not retried, so a mail outage cannot cause a resend storm.
    markSent(batch.map((item) => item.key));
    const lines = batch.length > 1 ? [`${batch.length} new events`, ...batch.map((item) => item.line)] : [batch[0].line];
    const message = { to: address, kind: 'owner-event', lines, count: batch.length };
    try {
      return Promise.resolve(mailer.enqueue ? mailer.enqueue(message) : mailer.send(message))
        // send() reports SMTP failures as { delivered: 'failed' } rather than rejecting.
        .then((result) => (result?.delivered === 'failed' ? log('failed', 'send_failed', batch.length) : log('sent', null, batch.length)),
          () => log('failed', 'send_failed', batch.length));
    } catch { log('failed', 'send_failed', batch.length); return Promise.resolve(); }
  }

  return {
    notify(event) {
      try {
        if (stopped || !plain(event) || !wanted.has(event.type)) return;
        const item = describe(event, now());
        if (item.line.length > LINE_MAX) item.line = `${item.line.slice(0, LINE_MAX - 3)}...`;
        if (queue.some((entry) => entry.key === item.key) || Object.hasOwn(readSent(), item.key)) return;
        if (queue.length >= QUEUE_MAX) { log('dropped', 'owner_queue_full'); return; }
        queue.push(item);
        // Quiet period: send soon, but never inline with the request that raised the event.
        if (!timer && !immediate) { immediate = setImmediate(() => { immediate = null; deliver(); }); immediate.unref?.(); }
      } catch { log('failed', 'internal'); }
    },
    async flush() {
      try {
        clearImmediate(immediate); immediate = null;
        cancel(timer); timer = null;
        await deliver();
      } catch { log('failed', 'internal'); }
    },
    stop() { stopped = true; clearImmediate(immediate); cancel(timer); immediate = timer = null; },
  };
}
