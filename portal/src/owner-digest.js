// Daily owner summary (portal/bin/owner-digest.js; default off). Collectors read portal state, the edge, the outbox and
// Caddy access logs and return aggregates only; each fails safe to { available: false } instead of throwing.
// Visitor counting keeps salted hashes of masked addresses in memory for one run; nothing about a visitor is
// returned, logged or stored. renderDigest() turns the aggregates into the 'owner-digest' mail lines.
import { createReadStream, readdirSync, readFileSync, lstatSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { createGunzip } from 'node:zlib';
import { createHash, randomBytes } from 'node:crypto';
import { isIPv4, isIPv6 } from 'node:net';
import { emptyAccounts } from './store.js';
import { createSuspensions } from './suspensions.js';
import { readTrials, readOverrides, trialInfo } from './trials.js';
import { maskEmail, mountain } from './owner-notify.js';

export const ZONE = 'America/Denver';
export const UNIQUE_CAP = 200000;
const HOUR = 3600000;
const ENDING_MS = 48 * HOUR;
const LIST_MAX = 20;
const LINE_MAX = 200;
const PATHS_MAX = 10000;
const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const parse = (value) => (typeof value === 'string' ? Date.parse(value) : NaN);
const pad = (n) => String(n).padStart(2, '0');
const own = (all, key) => (plain(all) && Object.hasOwn(all, key) ? all[key] : null);
const id = (value) => (typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,80}$/.test(value) ? value : '?');

// ---- Mountain-time calendar days ----

let partsFormat;
function zoned(ms) {
  partsFormat ||= new Intl.DateTimeFormat('en-US', { timeZone: ZONE, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
  const p = Object.fromEntries(partsFormat.formatToParts(new Date(ms)).map((part) => [part.type, Number(part.value)]));
  return { y: p.year, m: p.month, d: p.day, h: p.hour, mi: p.minute, s: p.second };
}
// Zone offset at an instant (local wall clock minus UTC), in ms.
const offset = (ms) => { const z = zoned(ms); const whole = ms - (((ms % 1000) + 1000) % 1000); return Date.UTC(z.y, z.m - 1, z.d, z.h, z.mi, z.s) - whole; };
// Local midnight never falls in a Denver DST gap (changes happen at 02:00), so two passes settle the offset.
function midnight(y, m, d) {
  const guess = Date.UTC(y, m - 1, d);
  return guess - offset(guess - offset(guess));
}
export const mtDay = (ms) => { const z = zoned(ms); return `${z.y}-${pad(z.m)}-${pad(z.d)}`; };

// The previous Mountain-time calendar day: [start, end) in ms; 23 or 25 hours long on DST change days.
export function digestWindow(nowMs) {
  const z = zoned(nowMs);
  const previous = new Date(Date.UTC(z.y, z.m - 1, z.d - 1));
  const [y, m, d] = [previous.getUTCFullYear(), previous.getUTCMonth() + 1, previous.getUTCDate()];
  return { day: `${y}-${pad(m)}-${pad(d)}`, start: midnight(y, m, d), end: midnight(z.y, z.m, z.d) };
}

// ---- Accounts and trials ----

// Returns { accounts, trials, tenants }; tenants ([{ id, paused }], non-suspended only) feeds collectHostnames and is
// null when suspensions cannot be read. Account emails are kept for rendering, which masks them by default.
export function collectAccounts({ store, now, window }) {
  const inWindow = (value) => { const at = parse(value); return Number.isFinite(at) && at >= window.start && at < window.end; };
  const out = { accounts: { available: false }, trials: { available: false }, tenants: null };
  let data;
  try { data = store.read('accounts', emptyAccounts()); } catch { return out; }
  if (!plain(data) || !Array.isArray(data.tenants) || !Array.isArray(data.users)) return out;
  const tenants = data.tenants.filter((tenant) => plain(tenant) && typeof tenant.id === 'string');
  const users = data.users.filter(plain);
  const emailOf = (tid) => users.find((user) => user.tenant_id === tid && typeof user.email === 'string')?.email ?? null;
  let suspended = null;
  try {
    const suspensions = createSuspensions(store);
    suspended = new Set(tenants.filter((tenant) => suspensions.has(tenant.id)).map((tenant) => tenant.id));
  } catch { /* suspended stays unknown */ }
  const created = tenants.filter((tenant) => inWindow(tenant.created_at));
  out.accounts = { available: true, signups: created.length, signups_open: created.filter((tenant) => tenant.source === 'open').length,
    signups_invite: created.filter((tenant) => tenant.source !== 'open').length,
    verified_in_window: users.filter((user) => inWindow(user.email_verified_at)).length,
    tenants: tenants.length, users: users.length, verified: users.filter((user) => Number.isFinite(parse(user.email_verified_at))).length,
    suspended: suspended ? suspended.size : null };
  let paused = new Set();
  try {
    if (!suspended) throw new Error('suspensions unavailable');
    const trials = readTrials(store).tenants;
    const overrides = readOverrides(store).tenants;
    let active = 0;
    const ending = [];
    for (const tenant of tenants) {
      if (suspended.has(tenant.id)) continue;
      const info = trialInfo(tenant, own(trials, tenant.id), own(overrides, tenant.id), now);
      if (!info?.active) continue;
      active++;
      const ends = Date.parse(info.ends_at);
      if (ends - now <= ENDING_MS) ending.push({ tenant_id: tenant.id, email: emailOf(tenant.id), ends_at: ends });
    }
    const pausedList = Object.entries(trials).filter(([, entry]) => entry.paused_at).map(([tid]) => ({ tenant_id: tid, email: emailOf(tid) }));
    paused = new Set(pausedList.map((entry) => entry.tenant_id));
    out.trials = { available: true, active, ending: ending.sort((a, b) => a.ends_at - b.ends_at), paused: pausedList };
  } catch { /* trials stay unavailable */ }
  if (suspended) out.tenants = tenants.filter((tenant) => !suspended.has(tenant.id)).map((tenant) => ({ id: tenant.id, paused: paused.has(tenant.id) }));
  return out;
}

// ---- Hostnames (edge) ----

function withTimeout(promise, ms) {
  let timer;
  const expired = new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms); });
  return Promise.race([promise, expired]).finally(() => clearTimeout(timer));
}

// One listHostnames call at a time. Stops early after three consecutive failures or once budgetMs is spent.
export async function collectHostnames({ edge, tenants, timeoutMs = 6000, budgetMs = 90000, now = Date.now }) {
  const out = { available: false, total: 0, active: 0, connected: 0, on_paused: 0, checked: 0, tenants: Array.isArray(tenants) ? tenants.length : 0 };
  if (!edge || typeof edge.listHostnames !== 'function' || !Array.isArray(tenants)) return out;
  const started = now();
  let streak = 0;
  for (const tenant of tenants) {
    if (streak >= 3 || now() - started > budgetMs) break;
    try {
      const result = await withTimeout(Promise.resolve().then(() => edge.listHostnames(tenant.id)), timeoutMs);
      if (!Array.isArray(result?.hostnames)) throw new Error('shape');
      const list = result.hostnames.filter(plain);
      out.total += list.length;
      out.active += list.filter((host) => host.status === 'active').length;
      out.connected += list.filter((host) => host.agent?.connected === true).length;
      if (tenant.paused) out.on_paused += list.length;
      out.checked++;
      streak = 0;
    } catch { streak++; }
  }
  out.available = out.checked === out.tenants;
  return out;
}

// ---- Mail health (outbox audit records) ----

// Counts records written in the window by kind and status; reads only kind and status, never the address.
// Records without a status are file-transport messages ('queued').
export function collectMailHealth({ outboxDir, window, maxFiles = 20000 }) {
  let names;
  try { names = readdirSync(outboxDir).filter((name) => name.endsWith('.json')).slice(0, maxFiles); } catch { return { available: false }; }
  const out = { available: true, total: 0, sent: 0, failed: 0, queued: 0, kinds: [], reasons: [] };
  const kinds = new Map(), reasons = new Map();
  const add = (map, key) => map.set(key, (map.get(key) || 0) + 1);
  for (const name of names) {
    let record;
    try {
      const stat = lstatSync(join(outboxDir, name));
      if (!stat.isFile() || stat.mtimeMs < window.start || stat.mtimeMs >= window.end) continue;
      record = JSON.parse(readFileSync(join(outboxDir, name), 'utf8'));
    } catch { continue; }
    if (!plain(record)) continue;
    out.total++;
    add(kinds, typeof record.kind === 'string' && /^[a-z][a-z-]{0,39}$/.test(record.kind) ? record.kind : 'other');
    if (record.status === 'sent') out.sent++;
    else if (typeof record.status === 'string' && record.status.startsWith('failed:')) {
      out.failed++;
      const reason = record.status.slice(7);
      add(reasons, /^[a-z][a-z_]{0,39}$/.test(reason) ? reason : 'other');
    } else out.queued++;
  }
  const sorted = (map) => [...map].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  out.kinds = sorted(kinds);
  out.reasons = sorted(reasons);
  return out;
}

// ---- Visitors (Caddy JSON access logs) ----

export const BOT_UA = /bot|crawl|spider|slurp|curl|wget|python|go-http|httpclient|headless|monitor|uptime|scan|preview|facebookexternalhit|bingpreview|ahrefs|semrush|petal|yandex|bytespider|gptbot|claudebot|ccbot|amazonbot|applebot|duckduckbot|googlebot/i;
const ASSET = /\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|xml|txt|json|map|webmanifest)$/i;

// Page paths: '/', a directory ('/x/'), an .html file or a final segment without an extension.
export function isPagePath(path) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('/.well-known/') || ASSET.test(path)) return false;
  const last = path.slice(path.lastIndexOf('/') + 1);
  return last === '' || /\.html$/i.test(last) || !last.includes('.');
}

function expandV6(ip) {
  let address = ip.split('%')[0];
  const tail = address.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (tail) {
    const [a, b, c, d] = tail[1].split('.').map(Number);
    address = `${address.slice(0, -tail[1].length)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, rest] = address.split('::');
  const left = head ? head.split(':') : [];
  const right = rest === undefined ? [] : rest ? rest.split(':') : [];
  const groups = rest === undefined ? left : [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
  return groups.map((group) => parseInt(group, 16));
}
// IPv4 to /24 and IPv6 to /48 (IPv4-mapped IPv6 as IPv4); the same result whether or not the input was already masked.
export function maskIp(value) {
  if (typeof value !== 'string') return '';
  const ip = value.trim();
  if (isIPv4(ip)) return `${ip.split('.').slice(0, 3).join('.')}.0/24`;
  if (!isIPv6(ip)) return '';
  const groups = expandV6(ip);
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) return `${groups[6] >> 8}.${groups[6] & 255}.${groups[7] >> 8}.0/24`;
  return `${groups.slice(0, 3).map((g) => g.toString(16)).join(':')}::/48`;
}

// Parsed access-log entry, or null for anything malformed.
function readEntry(line) {
  if (line.length > 65536) return null;
  let entry;
  try { entry = JSON.parse(line); } catch { return null; }
  if (!plain(entry) || !plain(entry.request)) return null;
  const ts = entry.ts;
  const ms = typeof ts === 'number' ? (ts > 1e11 ? ts : ts * 1000) : parse(ts);
  if (!Number.isFinite(ms)) return null;
  const request = entry.request;
  const uri = typeof request.uri === 'string' ? request.uri : '';
  const cut = uri.search(/[?#]/);
  const agents = plain(request.headers) ? request.headers['User-Agent'] : undefined;
  const ip = typeof request.client_ip === 'string' && request.client_ip ? request.client_ip : request.remote_ip;
  return { ms, method: request.method, status: entry.status, path: cut >= 0 ? uri.slice(0, cut) : uri, ip,
    ua: Array.isArray(agents) && typeof agents[0] === 'string' ? agents[0].slice(0, 1024) : '' };
}

function eachLine(path, onLine) {
  return new Promise((resolve, reject) => {
    const source = createReadStream(path);
    const input = path.endsWith('.gz') ? source.pipe(createGunzip()) : source;
    let failed = false;
    const lines = createInterface({ input, crlfDelay: Infinity });
    const fail = (error) => { if (failed) return; failed = true; lines.close(); source.destroy(); reject(error); };
    // readline re-emits input errors on the interface, so all three need a listener.
    source.on('error', fail);
    input.on('error', fail);
    lines.on('error', fail);
    lines.on('line', (line) => { if (!failed) onLine(line); });
    lines.on('close', () => { if (!failed) resolve(); });
  });
}

// Feeds every in-window entry to onEntry. A missing or unreadable file counts as failed; a file last written before
// the window cannot hold window lines and is skipped unread.
async function scanLogs(files, window, onEntry) {
  let read = 0, failed = 0;
  for (const file of files) {
    try {
      const stat = statSync(file);
      if (!stat.isFile()) throw new Error('not a file');
      if (stat.mtimeMs >= window.start) {
        await eachLine(file, (line) => {
          const entry = readEntry(line);
          if (entry && entry.ms >= window.start && entry.ms < window.end) onEntry(entry);
        });
      }
      read++;
    } catch { failed++; }
  }
  return { read, failed };
}

// Each configured log plus its rolled siblings ('<base>-<timestamp>.<ext>.gz') written since the window start.
export function logFiles({ logDir, names, window }) {
  const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  let listing;
  try { listing = readdirSync(logDir).sort(); } catch { listing = []; }
  const files = [];
  for (const name of names) {
    files.push(join(logDir, name));
    const dot = name.lastIndexOf('.');
    const [base, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ''];
    const rolled = new RegExp(`^${escape(base)}-\\d{4}-\\d{2}-\\d{2}T[0-9.-]+${escape(ext)}\\.gz$`);
    for (const sibling of listing.filter((item) => rolled.test(item))) {
      try { const stat = statSync(join(logDir, sibling)); if (stat.isFile() && stat.mtimeMs >= window.start) files.push(join(logDir, sibling)); } catch { /* raced with rotation */ }
    }
  }
  return [...new Set(files)];
}

const hasher = (salt) => (value) => createHash('sha256').update(`${salt}${value}`).digest('base64').slice(0, 22);
const safePath = (path) => path.replace(/[^A-Za-z0-9/._~%+-]/g, '?').slice(0, 100);
const isBot = (ua) => ua !== '' && BOT_UA.test(ua);

// Page views, unique visitors (salted hash of masked address + user agent, in memory only), bot page hits and top pages.
export async function countVisitors({ files, window, salt = randomBytes(32).toString('hex'), cap = UNIQUE_CAP }) {
  const hash = hasher(salt);
  const unique = new Set();
  const paths = new Map();
  let views = 0, bots = 0, capped = false;
  const { read, failed } = await scanLogs(files, window, (entry) => {
    if (entry.method !== 'GET' || !Number.isInteger(entry.status) || entry.status < 200 || entry.status > 399 || !isPagePath(entry.path)) return;
    if (isBot(entry.ua)) { bots++; return; }
    views++;
    const path = safePath(entry.path);
    if (paths.has(path) || paths.size < PATHS_MAX) paths.set(path, (paths.get(path) || 0) + 1);
    if (capped) return;
    const key = hash(`${maskIp(entry.ip)}|${entry.ua}`);
    if (unique.size < cap) unique.add(key); else if (!unique.has(key)) capped = true;
  });
  const top = [...paths].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 5);
  return { available: read > 0, partial: failed > 0, page_views: views, unique_visitors: capped ? `${cap}+` : unique.size, bot_hits: bots, top_paths: top };
}

// Sign-up page funnel: successful GET /signup requests (bots excluded) and how many distinct masked networks made them.
export async function countFunnel({ files, window, salt = randomBytes(32).toString('hex'), cap = UNIQUE_CAP }) {
  const hash = hasher(salt);
  const networks = new Set();
  let views = 0, capped = false;
  const { read, failed } = await scanLogs(files, window, (entry) => {
    if (entry.method !== 'GET' || entry.status !== 200 || entry.path !== '/signup' || isBot(entry.ua)) return;
    views++;
    const key = hash(maskIp(entry.ip));
    if (networks.size < cap) networks.add(key); else if (!networks.has(key)) capped = true;
  });
  return { available: read > 0, partial: failed > 0, signup_views: views, unique_networks: capped ? `${cap}+` : networks.size };
}

// ---- Rendering ----

const clip = (line) => {
  const text = String(line).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, '?');
  return text.length > LINE_MAX ? `${text.slice(0, LINE_MAX - 3)}...` : text;
};

// Short printable lines for the 'owner-digest' mail. Never includes IPs, user agents or hashes; account emails are
// masked unless showEmail.
export function renderDigest({ day, showEmail = false, accounts, trials, hostnames, mail, visitors, funnel } = {}) {
  const who = (email) => (typeof email !== 'string' || !email ? '?' : showEmail ? email : maskEmail(email));
  const lines = [`FastDog daily summary for ${/^\d{4}-\d{2}-\d{2}$/.test(day) ? day : '?'} (Mountain time)`, ''];
  const list = (items, format) => {
    for (const item of items.slice(0, LIST_MAX)) lines.push(format(item));
    if (items.length > LIST_MAX) lines.push(`  ... and ${items.length - LIST_MAX} more`);
  };
  if (accounts?.available) {
    lines.push(`Sign-ups: ${accounts.signups} new (${accounts.signups_open} open, ${accounts.signups_invite} invite); ${accounts.verified_in_window} emails verified`);
    lines.push(`  Totals: ${accounts.tenants} accounts, ${accounts.users} users, ${accounts.verified} verified, ${accounts.suspended ?? 'unknown'} suspended`);
  } else lines.push('Sign-ups: unavailable');
  if (trials?.available) {
    lines.push(`Trials: ${trials.active} active, ${trials.ending.length} ending within 48h, ${trials.paused.length} paused`);
    list(trials.ending, (item) => `  Ends ${mountain(item.ends_at)}: tenant ${id(item.tenant_id)} (${who(item.email)})`);
    list(trials.paused, (item) => `  Paused: tenant ${id(item.tenant_id)} (${who(item.email)})`);
  } else lines.push('Trials: unavailable');
  const hostCounts = (h) => `${h.total} total, ${h.active} active, ${h.connected} with a connected agent, ${h.on_paused} on paused trials`;
  if (hostnames?.available) lines.push(`Hostnames: ${hostCounts(hostnames)}`);
  else if (hostnames?.checked > 0) lines.push(`Hostnames: unavailable (partial, ${hostnames.checked} of ${hostnames.tenants} accounts: ${hostCounts(hostnames)})`);
  else lines.push('Hostnames: unavailable');
  if (mail?.available) {
    lines.push(`Mail: ${mail.total} messages (${mail.sent} sent, ${mail.failed} failed, ${mail.queued} queued in outbox)`);
    if (mail.kinds.length) lines.push(`  By kind: ${mail.kinds.map(([kind, n]) => `${kind} ${n}`).join(', ')}`);
    if (mail.reasons.length) lines.push(`  Failures: ${mail.reasons.map(([reason, n]) => `${reason} ${n}`).join(', ')}`);
  } else lines.push('Mail: unavailable');
  if (visitors === undefined || visitors === null) lines.push('Visitors: off');
  else if (visitors.reason === 'not_configured') lines.push('Visitors: not configured');
  else if (!visitors.available) lines.push('Visitors: unavailable');
  else {
    lines.push(`Visitors: ${visitors.page_views} page views, ${visitors.unique_visitors} unique visitors, ${visitors.bot_hits} bot hits${visitors.partial ? ' (some logs unreadable)' : ''}`);
    if (visitors.top_paths.length) lines.push(`  Top pages: ${visitors.top_paths.map(([path, n]) => `${path} ${n}`).join(', ')}`);
  }
  if (funnel) {
    lines.push(funnel.available ? `Funnel: ${funnel.signup_views} sign-up page views from ${funnel.unique_networks} networks${funnel.partial ? ' (some logs unreadable)' : ''}`
      : 'Funnel: unavailable');
  }
  return lines.map(clip);
}
