// Daily owner summary (portal/bin/owner-digest.js; default off). Collectors read portal state, the edge, the outbox and
// Caddy access logs and return aggregates only; each fails safe to { available: false } instead of throwing.
// Visitor counting keeps salted hashes of masked addresses in memory for one run; nothing about a visitor is
// returned, logged or stored. renderDigest() turns the aggregates into the 'owner-digest' mail lines.
import { createReadStream, readdirSync, readFileSync, lstatSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createGunzip } from 'node:zlib';
import { createHash, randomBytes } from 'node:crypto';
import { isIPv4, isIPv6 } from 'node:net';
import { normalizeEmail } from './tokens.js';
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

// Returns { accounts, internal, trials, tenants }; tenants ([{ id, paused }], non-suspended only) feeds collectHostnames and is
// null when suspensions cannot be read. Account emails are kept for rendering, which masks them by default.
export function collectAccounts({ store, now, window, config = {} }) {
  const inWindow = (value) => { const at = parse(value); return Number.isFinite(at) && at >= window.start && at < window.end; };
  const out = { accounts: { available: false }, trials: { available: false }, tenants: null };
  let data;
  try { data = store.read('accounts', emptyAccounts()); } catch { return out; }
  if (!plain(data) || !Array.isArray(data.tenants) || !Array.isArray(data.users)) return out;
  const tenants = data.tenants.filter((tenant) => plain(tenant) && typeof tenant.id === 'string');
  const users = data.users.filter(plain);
  const explicit = new Set(config.internalEmails || []);
  const owner = normalizeEmail(config.to);
  const internalUser = (user) => {
    if (user.internal === true || user.test === true) return true;
    const email = normalizeEmail(user.email);
    if (!email) return false;
    if (explicit.has(email)) return true;
    if (config.internalAuto === false) return false;
    const [local, domain] = email.split('@');
    return /(?:^|\.)(?:test|example|invalid|localhost|example\.com|example\.net|example\.org)$/.test(domain)
      || (owner && domain === owner.split('@')[1] && local.split('+')[0] === owner.split('@')[0].split('+')[0]);
  };
  const internalIds = new Set(users.filter(internalUser).map((user) => user.tenant_id));
  for (const tenant of tenants) if (tenant.internal === true || tenant.test === true) internalIds.add(tenant.id);
  const internal = tenants.filter((tenant) => internalIds.has(tenant.id));
  const customers = tenants.filter((tenant) => !internalIds.has(tenant.id));
  const customerUsers = users.filter((user) => !internalIds.has(user.tenant_id));
  out.internal = { tenants: internal.length, signups: internal.filter((tenant) => inWindow(tenant.created_at)).length };
  const emailOf = (tid) => users.find((user) => user.tenant_id === tid && typeof user.email === 'string')?.email ?? null;
  let suspended = null;
  try {
    const suspensions = createSuspensions(store);
    suspended = new Set(tenants.filter((tenant) => suspensions.has(tenant.id)).map((tenant) => tenant.id));
  } catch { /* suspended stays unknown */ }
  const created = customers.filter((tenant) => inWindow(tenant.created_at));
  out.accounts = { available: true, signups: created.length, signups_open: created.filter((tenant) => tenant.source === 'open').length,
    signups_invite: created.filter((tenant) => tenant.source !== 'open').length,
    verified_in_window: customerUsers.filter((user) => inWindow(user.email_verified_at)).length,
    tenants: customers.length, users: customerUsers.length, verified: customerUsers.filter((user) => Number.isFinite(parse(user.email_verified_at))).length,
    suspended: suspended ? customers.filter((tenant) => suspended.has(tenant.id)).length : null };
  let paused = new Set();
  try {
    if (!suspended) throw new Error('suspensions unavailable');
    const trials = readTrials(store).tenants;
    const overrides = readOverrides(store).tenants;
    let active = 0;
    const ending = [];
    for (const tenant of customers) {
      if (suspended.has(tenant.id)) continue;
      const info = trialInfo(tenant, own(trials, tenant.id), own(overrides, tenant.id), now);
      if (!info?.active) continue;
      active++;
      const ends = Date.parse(info.ends_at);
      if (ends - now <= ENDING_MS) ending.push({ tenant_id: tenant.id, email: emailOf(tenant.id), ends_at: ends });
    }
    const pausedList = Object.entries(trials).filter(([, entry]) => entry.paused_at).map(([tid]) => ({ tenant_id: tid, email: emailOf(tid) }));
    paused = new Set(pausedList.map((entry) => entry.tenant_id));
    out.trials = { available: true, active, ending: ending.sort((a, b) => a.ends_at - b.ends_at), paused: pausedList.filter((entry) => !internalIds.has(entry.tenant_id)) };
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

export const BOT_UA = /bot|crawl|spider|slurp|curl|wget|python|go-http|httpclient|headless|monitor|uptime|scan|preview|facebookexternalhit|bingpreview|ahrefs|semrush|petal|yandex|bytespider|gptbot|claudebot|ccbot|amazonbot|applebot|duckduckbot|googlebot|zgrab|masscan|nmap|nikto|sqlmap|httpx|okhttp|libwww|java\/|axios|node-fetch|scrapy|censys|expanse|l9explore|nuclei|wpscan/i;
// Superset of Verdict's inline probe pattern in verdict/src/engine/signals.js (a separate package).
export const PROBE_PATH = /(?:^|\/)(?:\.env(?:\.[^/]*)?|\.git|\.aws|\.ssh|\.svn|\.hg|\.DS_Store|phpinfo|php-info|_profiler|phpmyadmin|pma|wp-admin|wp-login(?:\.php)?|wp-content|wp-includes|xmlrpc\.php|cgi-bin|actuator|server-status|vendor\/phpunit|config\.(?:json|ya?ml))(?:\/|$)|\.(?:php|asp|aspx|jsp|cgi|bak|sql|zip|tar|gz|old|swp)$/i;
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
// IPv4 to /24 and IPv6 to /48 (IPv4-mapped IPv6 as IPv4); the same result whether or not the input was already
// masked, including a CIDR form such as '203.0.113.0/24'.
export function maskIp(value) {
  if (typeof value !== 'string') return '';
  const ip = value.trim().replace(/\/\d{1,3}$/, '');
  if (isIPv4(ip)) return `${ip.split('.').slice(0, 3).join('.')}.0/24`;
  if (!isIPv6(ip)) return '';
  const groups = expandV6(ip);
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) return `${groups[6] >> 8}.${groups[6] & 255}.${groups[7] >> 8}.0/24`;
  return `${groups.slice(0, 3).map((g) => g.toString(16)).join(':')}::/48`;
}

// Parsed access-log entry, null for a line that is empty once NUL bytes are removed, or SKIP for anything
// malformed or longer than LOG_LINE_MAX. Raw NULs are dropped first: a log truncated in place while Caddy kept
// it open without O_APPEND starts with a run of NULs glued to the next JSON line.
const LOG_LINE_MAX = 1024 * 1024;
const SKIP = Symbol('skip');
function readEntry(raw) {
  if (raw === OVERSIZE) return SKIP;
  const line = raw.includes('\0') ? raw.replaceAll('\0', '') : raw;
  if (line.trim() === '') return null;
  if (line.length > LOG_LINE_MAX) return SKIP;
  let entry;
  try { entry = JSON.parse(line); } catch { return SKIP; }
  if (!plain(entry) || !plain(entry.request)) return SKIP;
  const ts = entry.ts;
  const ms = typeof ts === 'number' ? (ts > 1e11 ? ts : ts * 1000) : parse(ts);
  if (!Number.isFinite(ms)) return SKIP;
  const request = entry.request;
  const uri = typeof request.uri === 'string' ? request.uri : '';
  const cut = uri.search(/[?#]/);
  const agents = plain(request.headers) ? request.headers['User-Agent'] : undefined;
  const ip = typeof request.client_ip === 'string' && request.client_ip ? request.client_ip : request.remote_ip;
  return { ms, method: request.method, status: entry.status, path: cut >= 0 ? uri.slice(0, cut) : uri, ip,
    ua: (Array.isArray(agents) && typeof agents[0] === 'string' ? agents[0] : typeof entry.user_agent === 'string' ? entry.user_agent : '').slice(0, 1024) };
}

const OVERSIZE = Symbol('oversize');
const NL = 0x0a;
const dropNul = (chunk) => (chunk.includes(0) ? Buffer.from(chunk.filter((byte) => byte !== 0)) : chunk);
// Streams a (optionally gzipped) log line by line with bounded memory: NUL bytes are dropped as they arrive, and a
// line that grows past LOG_LINE_MAX is discarded up to its newline and reported once as OVERSIZE.
function eachLine(path, onLine) {
  return new Promise((resolve, reject) => {
    const source = createReadStream(path);
    const input = path.endsWith('.gz') ? source.pipe(createGunzip()) : source;
    let failed = false, parts = [], size = 0, oversize = false;
    const fail = (error) => { if (failed) return; failed = true; source.destroy(); input.destroy?.(); reject(error); };
    const add = (piece) => {
      if (oversize || !piece.length) return;
      if (size + piece.length > LOG_LINE_MAX) { oversize = true; parts = []; size = 0; return; }
      parts.push(piece); size += piece.length;
    };
    const end = () => {
      if (oversize) onLine(OVERSIZE);
      else if (size) onLine(Buffer.concat(parts, size).toString('utf8'));
      parts = []; size = 0; oversize = false;
    };
    source.on('error', fail);
    input.on('error', fail);
    input.on('data', (chunk) => {
      if (failed) return;
      try {
        let at = 0;
        for (let nl = chunk.indexOf(NL); nl !== -1; nl = chunk.indexOf(NL, at)) { add(dropNul(chunk.subarray(at, nl))); end(); at = nl + 1; }
        add(dropNul(chunk.subarray(at)));
      } catch (error) { fail(error); }
    });
    input.on('end', () => { if (failed) return; try { end(); resolve(); } catch (error) { fail(error); } });
  });
}

// Feeds every in-window entry to onEntry. A missing or unreadable file counts as failed; a file last written before
// the window cannot hold window lines and is skipped unread. Malformed lines are counted, never kept.
async function scanLogs(files, window, onEntry) {
  let read = 0, failed = 0, skipped = 0;
  for (const file of files) {
    try {
      const stat = statSync(file);
      if (!stat.isFile()) throw new Error('not a file');
      if (stat.mtimeMs >= window.start) {
        await eachLine(file, (line) => {
          const entry = readEntry(line);
          if (entry === SKIP) skipped++;
          else if (entry && entry.ms >= window.start && entry.ms < window.end) onEntry(entry);
        });
      }
      read++;
    } catch { failed++; }
  }
  return { read, failed, skipped };
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
const isBot = (entry, shadow) => entry.ua === '' || BOT_UA.test(entry.ua) || PROBE_PATH.test(entry.path)
  || shadow.keys.has(`${maskIp(entry.ip)}|${entry.path}`);

// Bounded, run-local join; a failed read discards partial results and never fails the digest.
async function readShadow(file, window, cap = UNIQUE_CAP) {
  const keys = new Set();
  if (!file) return { keys, status: 'off' };
  try {
    if (!statSync(file).isFile()) throw new Error('not a file');
    await eachLine(file, (line) => {
      if (line === OVERSIZE || keys.size >= cap) return;
      let row;
      try { row = JSON.parse(line); } catch { return; }
      if (!plain(row)) return;
      const ms = typeof row.ts === 'number' ? (row.ts > 1e11 ? row.ts : row.ts * 1000) : parse(row.ts);
      if (ms < window.start || ms >= window.end || !Number.isFinite(ms)
        || !['challenge', 'block'].includes(row.action) || typeof row.path !== 'string' || !row.path.startsWith('/')) return;
      const prefix = maskIp(row.ip_prefix);
      if (prefix) keys.add(`${prefix}|${row.path.split(/[?#]/)[0]}`);
    });
    return { keys, status: 'on' };
  } catch { return { keys: new Set(), status: 'unavailable' }; }
}

// Page views, unique visitors (salted hash of masked address + user agent, in memory only), bot page hits and top pages.
export async function countVisitors({ files, window, salt = randomBytes(32).toString('hex'), cap = UNIQUE_CAP, shadowFile = null }) {
  const shadow = await readShadow(shadowFile, window);
  const hash = hasher(salt);
  const unique = new Set();
  const paths = new Map();
  const botPaths = new Map();
  const addPath = (map, path) => { const safe = safePath(path); if (map.has(safe) || map.size < PATHS_MAX) map.set(safe, (map.get(safe) || 0) + 1); };
  let views = 0, bots = 0, probes = 0, capped = false;
  const { read, failed, skipped } = await scanLogs(files, window, (entry) => {
    const probe = PROBE_PATH.test(entry.path);
    if (probe) { probes++; addPath(botPaths, entry.path); }
    if (entry.method !== 'GET' || !Number.isInteger(entry.status) || entry.status < 200 || entry.status > 399 || !isPagePath(entry.path)) return;
    if (isBot(entry, shadow)) { bots++; if (!probe) addPath(botPaths, entry.path); return; }
    views++;
    const path = safePath(entry.path);
    if (paths.has(path) || paths.size < PATHS_MAX) paths.set(path, (paths.get(path) || 0) + 1);
    if (capped) return;
    const key = hash(`${maskIp(entry.ip)}|${entry.ua}`);
    if (unique.size < cap) unique.add(key); else if (!unique.has(key)) capped = true;
  });
  const top = [...paths].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 5);
  return { available: read > 0, partial: failed > 0, page_views: views, unique_visitors: capped ? `${cap}+` : unique.size, bot_hits: bots, probe_hits: probes, top_paths: top,
    bot_top_paths: [...botPaths].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 3),
    skipped_lines: skipped, shadow_join: shadow.status };
}

// Sign-up page funnel: successful GET /signup requests (bots excluded) and how many distinct masked networks made them.
export async function countFunnel({ files, window, salt = randomBytes(32).toString('hex'), cap = UNIQUE_CAP, shadowFile = null }) {
  const shadow = await readShadow(shadowFile, window);
  const hash = hasher(salt);
  const networks = new Set();
  let views = 0, capped = false;
  const { read, failed, skipped } = await scanLogs(files, window, (entry) => {
    if (entry.method !== 'GET' || entry.status !== 200 || entry.path !== '/signup' || isBot(entry, shadow)) return;
    views++;
    const key = hash(maskIp(entry.ip));
    if (networks.size < cap) networks.add(key); else if (!networks.has(key)) capped = true;
  });
  return { available: read > 0, partial: failed > 0, signup_views: views, unique_networks: capped ? `${cap}+` : networks.size,
    skipped_lines: skipped, shadow_join: shadow.status };
}

// ---- Rendering ----

const clip = (line) => {
  const text = String(line).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, '?');
  return text.length > LINE_MAX ? `${text.slice(0, LINE_MAX - 3)}...` : text;
};

// Short printable lines for the 'owner-digest' mail. Never includes IPs, user agents or hashes; account emails are
// masked unless showEmail.
export function renderDigest({ day, showEmail = false, accounts, internal, trials, hostnames, mail, visitors, funnel } = {}) {
  const who = (email) => (typeof email !== 'string' || !email ? '?' : showEmail ? email : maskEmail(email));
  const lines = [`FastDog daily summary for ${/^\d{4}-\d{2}-\d{2}$/.test(day) ? day : '?'} (Mountain time)`, ''];
  // Only the number of skipped log lines is shown, never their content.
  const skipped = (result) => (Number.isInteger(result?.skipped_lines) && result.skipped_lines > 0 ? ` (${result.skipped_lines} malformed log lines skipped)` : '');
  const list = (items, format) => {
    for (const item of items.slice(0, LIST_MAX)) lines.push(format(item));
    if (items.length > LIST_MAX) lines.push(`  ... and ${items.length - LIST_MAX} more`);
  };
  if (accounts?.available) {
    lines.push(`Sign-ups: ${accounts.signups} new (${accounts.signups_open} open, ${accounts.signups_invite} invite); ${accounts.verified_in_window} emails verified`);
    lines.push(`  Totals: ${accounts.tenants} accounts, ${accounts.users} users, ${accounts.verified} verified, ${accounts.suspended ?? 'unknown'} suspended`);
    if (internal?.tenants > 0) lines.push(`  Internal/test: ${internal.tenants} accounts (excluded above)`);
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
    lines.push(`Visitors: ${visitors.page_views} page views, ${visitors.unique_visitors} unique human visitors; bots: ${visitors.bot_hits} bot page hits, ${visitors.probe_hits ?? 0} probe requests${visitors.partial ? ' (some logs unreadable)' : ''}${skipped(visitors)}`);
    if (visitors.top_paths.length) lines.push(`  Top pages: ${visitors.top_paths.map(([path, n]) => `${path} ${n}`).join(', ')}`);
  }
  if (visitors?.available && visitors.bot_top_paths?.length) lines.push(`  Top probe paths: ${visitors.bot_top_paths.map(([path, n]) => `${path} ${n}`).join(', ')}`);
  if (funnel) {
    lines.push(funnel.available ? `Funnel: ${funnel.signup_views} sign-up page views from ${funnel.unique_networks} networks${funnel.partial ? ' (some logs unreadable)' : ''}${skipped(funnel)}`
      : 'Funnel: unavailable');
  }
  return lines.map(clip);
}
