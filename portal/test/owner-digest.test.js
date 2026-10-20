import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync, existsSync, mkdirSync, utimesSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';
import { digestWindow, mtDay, collectAccounts, collectHostnames, collectMailHealth, countVisitors, countFunnel, logFiles, maskIp, isPagePath,
  renderDigest } from '../src/owner-digest.js';
import { renderMail } from '../src/mail-templates.js';
import { createStore, emptyAccounts } from '../src/store.js';
import { temporary, fakeSecret } from './helpers.js';

const HOUR = 3600000;
const DAY = 24 * HOUR;
const OWNER = 'owner@example.test';
const NOW = Date.parse('2026-10-20T14:00:00Z'); // 08:00 MDT
const WINDOW = digestWindow(NOW);
const tid = (letter) => `t_${letter.repeat(20)}`;
const iso = (ms) => new Date(ms).toISOString();
const root = fileURLToPath(new URL('../../', import.meta.url));
const bin = fileURLToPath(new URL('../bin/owner-digest.js', import.meta.url));
// Nothing derived from a visitor may leave the counters: no addresses, user agents or hash-like strings
// (visitor keys are 22 base64 characters; tenant ids have 20 after 't_').
const LEAK = /203\.0\.113|198\.51\.100|2001:db8|Mozilla|Googlebot|Firefox|Safari|[A-Za-z0-9+/=]{22,}/i;

// ---- Window ----

test('digestWindow: previous Mountain-time day, DST-correct', () => {
  assert.deepEqual(WINDOW, { day: '2026-10-19', start: Date.parse('2026-10-19T06:00:00Z'), end: Date.parse('2026-10-20T06:00:00Z') });
  const fall = digestWindow(Date.parse('2026-11-02T15:00:00Z'));
  assert.deepEqual(fall, { day: '2026-11-01', start: Date.parse('2026-11-01T06:00:00Z'), end: Date.parse('2026-11-02T07:00:00Z') });
  assert.equal(fall.end - fall.start, 25 * HOUR);
  const spring = digestWindow(Date.parse('2026-03-09T14:00:00Z'));
  assert.deepEqual(spring, { day: '2026-03-08', start: Date.parse('2026-03-08T07:00:00Z'), end: Date.parse('2026-03-09T06:00:00Z') });
  assert.equal(spring.end - spring.start, 23 * HOUR);
  // Around local midnight and across a year end.
  assert.equal(digestWindow(Date.parse('2026-10-20T06:00:00Z')).day, '2026-10-19');
  assert.equal(digestWindow(Date.parse('2026-10-20T05:59:59Z')).day, '2026-10-18');
  assert.equal(digestWindow(Date.parse('2027-01-01T15:00:00Z')).day, '2026-12-31');
  assert.equal(mtDay(NOW), '2026-10-20');
  assert.equal(mtDay(Date.parse('2026-10-20T05:59:59Z')), '2026-10-19');
});

// ---- Accounts ----

function seedState(store) {
  const created = (ms, extra = {}) => ({ name: '', hostname_limit: 1, status: 'active', created_at: iso(ms), ...extra });
  const trial = { plan: 'trial', source: 'open' };
  const tenants = [
    { id: tid('a'), ...created(Date.parse('2026-10-19T12:00:00Z'), trial) },
    { id: tid('b'), ...created(WINDOW.start, { plan: 'pro' }) },
    // Ends 1 s inside / 1 s outside the 48-hour notice.
    { id: tid('c'), ...created(NOW + 48 * HOUR - 1000 - 7 * DAY, trial) },
    { id: tid('d'), ...created(NOW + 48 * HOUR + 1000 - 7 * DAY, trial) },
    { id: tid('e'), ...created(Date.parse('2026-10-01T00:00:00Z'), trial) },
    { id: tid('f'), ...created(Date.parse('2026-10-19T10:00:00Z'), trial) },
    { id: tid('g'), ...created(WINDOW.end, { plan: 'hobby', source: 'open' }) },
  ];
  const verified = { a: '2026-10-19T13:00:00Z', b: '2026-10-18T13:00:00Z', c: '2026-10-19T23:59:00Z' };
  const users = tenants.map((tenant) => {
    const letter = tenant.id.slice(2, 3);
    return { id: `user-${letter}`, tenant_id: tenant.id, email: `user${letter}@example.com`, email_verified_at: verified[letter] ?? null };
  });
  store.write('accounts', { ...emptyAccounts(), tenants, users });
  store.write('trials', { tenants: { [tid('e')]: { paused_at: '2026-10-09T01:00:00.000Z' } } });
  store.write('suspensions', { tenants: { [tid('f')]: { at: '2026-10-19T11:00:00.000Z', reason: 'test', revoked_before: 0 } } });
  return tenants;
}

test('collectAccounts: sign-ups, verification, totals, trials ending and paused', (t) => {
  const store = createStore(temporary(t));
  seedState(store);
  const result = collectAccounts({ store, now: NOW, window: WINDOW });
  assert.deepEqual(result.accounts, { available: true, signups: 3, signups_open: 2, signups_invite: 1, verified_in_window: 2,
    tenants: 7, users: 7, verified: 3, suspended: 1 });
  assert.equal(result.trials.available, true);
  assert.equal(result.trials.active, 3);
  assert.deepEqual(result.trials.ending, [{ tenant_id: tid('c'), email: 'userc@example.com', ends_at: NOW + 48 * HOUR - 1000 }]);
  assert.deepEqual(result.trials.paused, [{ tenant_id: tid('e'), email: 'usere@example.com' }]);
  assert.deepEqual(result.tenants.map((tenant) => tenant.id), ['a', 'b', 'c', 'd', 'e', 'g'].map(tid));
  assert.deepEqual(result.tenants.filter((tenant) => tenant.paused).map((tenant) => tenant.id), [tid('e')]);
  // An override extension moves a trial out of the 48-hour notice.
  store.write('trial_overrides', { tenants: { [tid('c')]: { extra_days: 3 } } });
  assert.deepEqual(collectAccounts({ store, now: NOW, window: WINDOW }).trials.ending, []);
});

test('collectAccounts: unreadable files mark only their sections unavailable', (t) => {
  const dir = temporary(t);
  const store = createStore(dir);
  seedState(store);
  for (const content of ['{"tenants":[]}', '{not json', '[]']) {
    writeFileSync(join(dir, 'trials.json'), content);
    const result = collectAccounts({ store, now: NOW, window: WINDOW });
    assert.equal(result.accounts.available, true, content);
    assert.deepEqual(result.trials, { available: false }, content);
    assert.equal(result.tenants.length, 6, content);
  }
  writeFileSync(join(dir, 'suspensions.json'), '{"tenants":[1]}');
  const noSuspensions = collectAccounts({ store, now: NOW, window: WINDOW });
  assert.equal(noSuspensions.accounts.suspended, null);
  assert.equal(noSuspensions.tenants, null);
  writeFileSync(join(dir, 'accounts.json'), '{"tenants":{}}');
  assert.deepEqual(collectAccounts({ store, now: NOW, window: WINDOW }), { accounts: { available: false }, trials: { available: false }, tenants: null });
  writeFileSync(join(dir, 'accounts.json'), 'garbage');
  assert.doesNotThrow(() => collectAccounts({ store, now: NOW, window: WINDOW }));
});

// ---- Hostnames ----

function recordingEdge(data, { fail = new Set(), hang = new Set() } = {}) {
  let inFlight = 0;
  const stats = { calls: [], maxInFlight: 0 };
  const edge = {
    async listHostnames(id) {
      stats.calls.push(id);
      inFlight++;
      stats.maxInFlight = Math.max(stats.maxInFlight, inFlight);
      try {
        if (hang.has(id)) await new Promise(() => {});
        await new Promise((resolve) => setTimeout(resolve, 5));
        if (fail.has(id)) throw new Error('edge down');
        return { hostnames: data[id] ?? [] };
      } finally { inFlight--; }
    },
  };
  return { edge, stats };
}
const hostData = {
  [tid('a')]: [{ hostname: 'a.example.test', status: 'active', agent: { connected: true } }, { hostname: 'b.example.test', status: 'pending' }],
  [tid('b')]: [{ hostname: 'c.example.test', status: 'active', agent: { connected: false } }],
  [tid('c')]: [{ hostname: 'd.example.test', status: 'active', agent: { connected: true } }],
};
const hostTenants = [{ id: tid('a'), paused: false }, { id: tid('b'), paused: true }, { id: tid('c'), paused: false }];

test('collectHostnames: sequential counts; a failing tenant marks the section unavailable with partial counts', async () => {
  const ok = recordingEdge(hostData);
  assert.deepEqual(await collectHostnames({ edge: ok.edge, tenants: hostTenants }),
    { available: true, total: 4, active: 3, connected: 2, on_paused: 1, checked: 3, tenants: 3 });
  assert.equal(ok.stats.maxInFlight, 1, 'never parallel');
  assert.deepEqual(ok.stats.calls, hostTenants.map((tenant) => tenant.id));
  const partial = recordingEdge(hostData, { fail: new Set([tid('b')]) });
  assert.deepEqual(await collectHostnames({ edge: partial.edge, tenants: hostTenants }),
    { available: false, total: 3, active: 2, connected: 2, on_paused: 0, checked: 2, tenants: 3 });
  const slow = recordingEdge(hostData, { hang: new Set([tid('a')]) });
  const timed = await collectHostnames({ edge: slow.edge, tenants: hostTenants, timeoutMs: 20 });
  assert.equal(timed.available, false);
  assert.equal(timed.checked, 2);
  // Three consecutive failures stop the run; no edge or no tenant list is simply unavailable.
  const many = Array.from({ length: 6 }, (_, i) => ({ id: tid('hijklm'[i]), paused: false }));
  const down = recordingEdge({}, { fail: new Set(many.map((tenant) => tenant.id)) });
  assert.equal((await collectHostnames({ edge: down.edge, tenants: many })).checked, 0);
  assert.equal(down.stats.calls.length, 3);
  assert.equal((await collectHostnames({ edge: null, tenants: hostTenants })).available, false);
  assert.equal((await collectHostnames({ edge: ok.edge, tenants: null })).available, false);
  assert.equal((await collectHostnames({ edge: { listHostnames() { throw new Error('sync'); } }, tenants: hostTenants })).available, false);
});

// ---- Mail health ----

test('collectMailHealth: counts window records by kind and status without addresses', (t) => {
  const dir = temporary(t);
  const write = (name, record, at = WINDOW.start + HOUR) => {
    writeFileSync(join(dir, name), typeof record === 'string' ? record : JSON.stringify(record));
    utimesSync(join(dir, name), at / 1000, at / 1000);
  };
  write('1.json', { to: 'a@example.test', kind: 'verify-email', link: '[redacted]', status: 'sent' });
  write('2.json', { to: 'b@example.test', kind: 'verify-email', link: '[redacted]', status: 'failed:auth_failed' });
  write('3.json', { to: 'c@example.test', kind: 'owner-event', status: 'failed:recipient_cap' });
  write('4.json', { to: 'd@example.test', kind: 'invite', link: 'x', code: 'y' });
  write('5.json', { to: 'e@example.test', kind: 'invite', status: 'sent' }, WINDOW.start - 1000);
  write('6.json', { to: 'f@example.test', kind: 'invite', status: 'sent' }, WINDOW.end);
  write('7.json', '{broken');
  write('8.txt', { kind: 'invite' });
  mkdirSync(join(dir, '.budget'));
  const result = collectMailHealth({ outboxDir: dir, window: WINDOW });
  assert.deepEqual(result, { available: true, total: 4, sent: 1, failed: 2, queued: 1,
    kinds: [['verify-email', 2], ['invite', 1], ['owner-event', 1]], reasons: [['auth_failed', 1], ['recipient_cap', 1]] });
  assert.ok(!JSON.stringify(result).includes('@'));
  assert.deepEqual(collectMailHealth({ outboxDir: join(dir, 'missing'), window: WINDOW }), { available: false });
});

// ---- Visitors ----

const UA = 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0';
const UA2 = 'Mozilla/5.0 (Macintosh) Safari/605.1.15';
const IN = WINDOW.start + 2 * HOUR;
function logLine({ ts = IN, ip = '203.0.113.7', ua = UA, method = 'GET', uri = '/', status = 200, client = true } = {}) {
  return JSON.stringify({ level: 'info', ts: ts / 1000, logger: 'http.log.access.log0', msg: 'handled request',
    request: { remote_ip: ip, ...(client ? { client_ip: ip } : {}), proto: 'HTTP/2.0', method, host: 'www.example.test', uri,
      headers: ua === null ? { Accept: ['*/*'] } : { 'User-Agent': [ua], Accept: ['*/*'] } }, status, size: 10 });
}
// Seven page views from four visitors (by masked network + user agent), one bot page hit; everything else excluded.
const siteEntries = [
  { ip: '203.0.113.7', uri: '/' },
  { ip: '203.0.113.99', uri: '/pricing' },
  { ip: '2001:db8:1:2::5', uri: '/docs/', status: 304 },
  { ip: '2001:db8:1:ffff::9', uri: '/about.html' },
  { ip: '203.0.113.7', ua: UA2, uri: '/pricing?plan=pro' },
  { ip: '198.51.100.4', ua: null, uri: '/' },
  { ip: '198.51.100.200', ua: null, uri: '/x', client: false },
  { ip: '198.51.100.9', ua: 'Mozilla/5.0 (compatible; Googlebot/2.1)', uri: '/pricing' },
  { uri: '/style.css' }, { uri: '/logo.png' }, { uri: '/app.js' }, { uri: '/site.webmanifest' }, { uri: '/robots.txt' },
  { uri: '/.well-known/acme-challenge/x' }, { uri: '/missing', status: 404 }, { uri: '/', status: 500 }, { uri: '/', method: 'POST' },
  { uri: '/', method: 'HEAD' }, { ts: WINDOW.start - 1 }, { ts: WINDOW.end },
];
const maskedCopy = (entry) => ({ ...entry, ip: maskIp(entry.ip ?? '203.0.113.7').replace(/\/\d+$/, '').replace(/::$/, '::') });
const writeLog = (path, lines, mtime = WINDOW.end + HOUR) => {
  const text = `${lines.join('\n')}\n`;
  writeFileSync(path, path.endsWith('.gz') ? gzipSync(text) : text);
  utimesSync(path, mtime / 1000, mtime / 1000);
};

test('maskIp and page path rules', () => {
  assert.equal(maskIp('203.0.113.77'), '203.0.113.0/24');
  assert.equal(maskIp('203.0.113.0'), '203.0.113.0/24');
  assert.equal(maskIp('2001:db8:1:2::5'), '2001:db8:1::/48');
  assert.equal(maskIp('2001:db8:1::'), '2001:db8:1::/48');
  assert.equal(maskIp('2001:0db8:0001:ffff:0:0:0:9'), '2001:db8:1::/48');
  assert.equal(maskIp('::ffff:203.0.113.5'), '203.0.113.0/24');
  assert.equal(maskIp('fe80::1%eth0'), 'fe80:0:0::/48');
  for (const bad of ['', 'nope', undefined, '203.0.113.7:443']) assert.equal(maskIp(bad), '');
  for (const path of ['/', '/docs/', '/about.html', '/pricing', '/a/b']) assert.equal(isPagePath(path), true, path);
  for (const path of ['/a.css', '/a.JS', '/i.svg', '/f.woff2', '/favicon.ico', '/sitemap.xml', '/x.json', '/a.js.map', '/m.webmanifest',
    '/wp-login.php', '/.well-known/security', '', 'x']) assert.equal(isPagePath(path), false, path);
});

test('countVisitors: page views, unique visitors and bots; masked and unmasked logs agree; nothing identifying returned', async (t) => {
  const dir = temporary(t);
  const lines = [...siteEntries.map(logLine), 'not json', '{"ts":"x"}', '', JSON.stringify({ ts: IN / 1000 }), '[1,2]'];
  writeLog(join(dir, 'full.json'), lines);
  writeLog(join(dir, 'masked.json'), siteEntries.map((entry) => logLine(maskedCopy(entry))));
  const full = await countVisitors({ files: [join(dir, 'full.json')], window: WINDOW });
  assert.deepEqual(full, { available: true, partial: false, page_views: 7, unique_visitors: 4, bot_hits: 1,
    top_paths: [['/', 2], ['/pricing', 2], ['/about.html', 1], ['/docs/', 1], ['/x', 1]] });
  const masked = await countVisitors({ files: [join(dir, 'masked.json')], window: WINDOW });
  assert.deepEqual(masked, full);
  assert.doesNotMatch(JSON.stringify(full), LEAK);
  // A per-run cap keeps memory bounded.
  assert.equal((await countVisitors({ files: [join(dir, 'full.json')], window: WINDOW, cap: 2 })).unique_visitors, '2+');
  // Missing files are unavailable without throwing; a mix is partial.
  assert.deepEqual(await countVisitors({ files: [join(dir, 'missing.json')], window: WINDOW }),
    { available: false, partial: true, page_views: 0, unique_visitors: 0, bot_hits: 0, top_paths: [] });
  const mixed = await countVisitors({ files: [join(dir, 'full.json'), join(dir, 'missing.json')], window: WINDOW });
  assert.equal(mixed.available, true);
  assert.equal(mixed.partial, true);
  // A file last written before the window is not read.
  writeLog(join(dir, 'stale.json'), [logLine()], WINDOW.start - HOUR);
  assert.equal((await countVisitors({ files: [join(dir, 'stale.json')], window: WINDOW })).page_views, 0);
  // Odd paths are reduced to a safe character set.
  writeLog(join(dir, 'odd.json'), [logLine({ uri: '/u/someone@example' }), logLine({ uri: '/a b‮/' })]);
  assert.deepEqual((await countVisitors({ files: [join(dir, 'odd.json')], window: WINDOW })).top_paths, [['/a?b?/', 1], ['/u/someone?example', 1]]);
});

test('logFiles and countVisitors: rolled .gz siblings count only when written since the window start', async (t) => {
  const dir = temporary(t);
  writeLog(join(dir, 'access-apex.json'), [logLine()]);
  const fresh = 'access-apex-2026-10-19T18-00-00.000.json.gz';
  const old = 'access-apex-2026-10-10T00-00-00.000.json.gz';
  writeLog(join(dir, fresh), [logLine({ ip: '198.51.100.50', ua: UA2, uri: '/start' })], WINDOW.start + 12 * HOUR);
  writeLog(join(dir, old), [logLine({ ip: '198.51.100.60', uri: '/old' })], WINDOW.start - DAY);
  writeLog(join(dir, 'access-apex-www-2026-10-19T18-00-00.000.json.gz'), [logLine({ uri: '/other-site' })], WINDOW.start + HOUR);
  writeLog(join(dir, 'access-apex.log'), [logLine({ uri: '/wrong-ext' })]);
  writeFileSync(join(dir, 'access-apex-2026-10-19T19-00-00.000.json.gz'), 'not gzip');
  utimesSync(join(dir, 'access-apex-2026-10-19T19-00-00.000.json.gz'), (WINDOW.start + HOUR) / 1000, (WINDOW.start + HOUR) / 1000);
  const files = logFiles({ logDir: dir, names: ['access-apex.json'], window: WINDOW });
  assert.deepEqual(files.map((file) => relative(dir, file)), ['access-apex.json', fresh, 'access-apex-2026-10-19T19-00-00.000.json.gz']);
  assert.deepEqual(logFiles({ logDir: dir, names: ['x.log'], window: WINDOW }).map((file) => relative(dir, file)), ['x.log']);
  const result = await countVisitors({ files, window: WINDOW });
  assert.deepEqual(result.top_paths, [['/', 1], ['/start', 1]]);
  assert.equal(result.unique_visitors, 2);
  assert.equal(result.partial, true, 'corrupt archive is reported, not thrown');
  assert.deepEqual(logFiles({ logDir: join(dir, 'missing'), names: ['a.json'], window: WINDOW }).map((file) => relative(dir, file)), ['missing/a.json']);
});

test('countFunnel: GET 200 /signup views and distinct masked networks', async (t) => {
  const dir = temporary(t);
  writeLog(join(dir, 'portal.json'), [
    logLine({ ip: '203.0.113.7', uri: '/signup' }), logLine({ ip: '203.0.113.8', uri: '/signup' }), logLine({ ip: '198.51.100.1', uri: '/signup' }),
    logLine({ ip: '2001:db8:5::1', uri: '/signup?ref=pricing' }), logLine({ uri: '/signup', status: 302 }), logLine({ uri: '/signup', method: 'POST' }),
    logLine({ uri: '/signup', ua: 'curl/8.0' }), logLine({ uri: '/login' }), logLine({ uri: '/signup', ts: WINDOW.end }),
  ]);
  const result = await countFunnel({ files: [join(dir, 'portal.json')], window: WINDOW });
  assert.deepEqual(result, { available: true, partial: false, signup_views: 4, unique_networks: 3 });
  assert.doesNotMatch(JSON.stringify(result), LEAK);
  assert.equal((await countFunnel({ files: [join(dir, 'none.json')], window: WINDOW })).available, false);
});

// ---- Rendering ----

async function digestData(t, showEmail) {
  const store = createStore(temporary(t));
  seedState(store);
  const { accounts, trials } = collectAccounts({ store, now: NOW, window: WINDOW });
  const dir = temporary(t);
  writeLog(join(dir, 'site.json'), siteEntries.map(logLine));
  return { day: WINDOW.day, showEmail, accounts, trials,
    hostnames: await collectHostnames({ edge: recordingEdge(hostData).edge, tenants: hostTenants }),
    mail: { available: true, total: 2, sent: 1, failed: 1, queued: 0, kinds: [['verify-email', 2]], reasons: [['auth_failed', 1]] },
    visitors: await countVisitors({ files: [join(dir, 'site.json')], window: WINDOW }),
    funnel: { available: true, partial: false, signup_views: 4, unique_networks: 3 } };
}

test('renderDigest: sections, masked addresses by default, short printable lines, no visitor data', async (t) => {
  const masked = renderDigest(await digestData(t, false));
  assert.deepEqual(masked, [
    'FastDog daily summary for 2026-10-19 (Mountain time)', '',
    'Sign-ups: 3 new (2 open, 1 invite); 2 emails verified',
    '  Totals: 7 accounts, 7 users, 3 verified, 1 suspended',
    'Trials: 3 active, 1 ending within 48h, 1 paused',
    `  Ends 2026-10-22 07:59 MT: tenant ${tid('c')} (u***@example.com)`,
    `  Paused: tenant ${tid('e')} (u***@example.com)`,
    'Hostnames: 4 total, 3 active, 2 with a connected agent, 1 on paused trials',
    'Mail: 2 messages (1 sent, 1 failed, 0 queued in outbox)',
    '  By kind: verify-email 2',
    '  Failures: auth_failed 1',
    'Visitors: 7 page views, 4 unique visitors, 1 bot hits',
    '  Top pages: / 2, /pricing 2, /about.html 1, /docs/ 1, /x 1',
    'Funnel: 4 sign-up page views from 3 networks',
  ]);
  const text = masked.join('\n');
  assert.ok(text.includes('@') && !/[a-z0-9]@/i.test(text), 'only masked addresses (x***@domain)');
  assert.doesNotMatch(text, LEAK);
  const full = renderDigest(await digestData(t, true)).join('\n');
  assert.ok(full.includes('userc@example.com') && full.includes('usere@example.com'));
  assert.doesNotMatch(full, LEAK);
  for (const lines of [masked, full.split('\n')]) {
    assert.ok(lines.every((line) => line.length <= 200));
    assert.doesNotThrow(() => renderMail({ kind: 'owner-digest', lines, date: WINDOW.day }));
  }
});

test('renderDigest: unavailable sections, long lists and hostile values stay within mail limits', () => {
  const lines = renderDigest({ day: WINDOW.day, accounts: { available: false }, trials: { available: false },
    hostnames: { available: false, checked: 0 }, mail: { available: false } });
  assert.deepEqual(lines.slice(2), ['Sign-ups: unavailable', 'Trials: unavailable', 'Hostnames: unavailable', 'Mail: unavailable', 'Visitors: off']);
  assert.deepEqual(renderDigest({ day: 'x', visitors: { available: false, reason: 'not_configured' }, funnel: { available: false } }).slice(-2),
    ['Visitors: not configured', 'Funnel: unavailable']);
  assert.equal(renderDigest({}).at(0), 'FastDog daily summary for ? (Mountain time)');
  const partial = renderDigest({ hostnames: { available: false, checked: 1, tenants: 3, total: 2, active: 1, connected: 0, on_paused: 0 } });
  assert.ok(partial.includes('Hostnames: unavailable (partial, 1 of 3 accounts: 2 total, 1 active, 0 with a connected agent, 0 on paused trials)'));
  const ending = Array.from({ length: 25 }, (_, i) => ({ tenant_id: `t_${i}‮`, email: `${'x'.repeat(300)}${i}@example.com`, ends_at: NOW }));
  const long = renderDigest({ day: WINDOW.day, showEmail: true, trials: { available: true, active: 25, ending, paused: [] },
    visitors: { available: true, partial: true, page_views: 1, unique_visitors: '200000+', bot_hits: 0, top_paths: [[`/${'p'.repeat(300)}`, 1]] } });
  assert.ok(long.includes('  ... and 5 more'));
  assert.equal(long.filter((line) => line.startsWith('  Ends ')).length, 20);
  assert.ok(long.some((line) => line.includes('tenant ? (')));
  assert.ok(long.includes('Visitors: 1 page views, 200000+ unique visitors, 0 bot hits (some logs unreadable)'));
  assert.doesNotThrow(() => renderMail({ kind: 'owner-digest', lines: long }));
});

// ---- CLI ----

async function refusedUrl() {
  const probe = createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address();
  await new Promise((resolve) => probe.close(resolve));
  return `http://127.0.0.1:${port}`;
}
async function cli(t) {
  const state = temporary(t);
  const store = createStore(state);
  store.write('accounts', { ...emptyAccounts(),
    tenants: [{ id: tid('a'), name: '', plan: 'trial', hostname_limit: 1, status: 'active', source: 'open', created_at: '2026-10-19T12:00:00.000Z' }],
    users: [{ id: 'user-a', tenant_id: tid('a'), email: 'customer@example.com', email_verified_at: '2026-10-19T12:30:00.000Z' }] });
  const logs = temporary(t);
  writeLog(join(logs, 'access-apex.json'), [logLine(), logLine({ uri: '/style.css' })]);
  const secrets = { PORTAL_KEY: fakeSecret(), SMTP_PASS: fakeSecret() };
  const base = { STATE_DIRECTORY: state, MAIL_TRANSPORT: 'file', EDGE_INTERNAL_URL: await refusedUrl(), ...secrets,
    OWNER_NOTIFY_EMAIL: OWNER, OWNER_DIGEST_ENABLED: '1', OWNER_DIGEST_LOG_DIR: logs, OWNER_DIGEST_SITE_LOGS: 'access-apex.json',
    ...(process.env.NODE_OPTIONS ? { NODE_OPTIONS: process.env.NODE_OPTIONS } : {}) };
  const outputs = [];
  const run = (args = [], env = {}) => {
    const result = spawnSync(process.execPath, [bin, ...args, '--now=2026-10-20T14:00:00Z'], { env: { ...base, ...env }, encoding: 'utf8', timeout: 60000 });
    outputs.push(result.stdout, result.stderr);
    const json = result.stdout.trim().split('\n').filter((line) => line.startsWith('{')).map((line) => JSON.parse(line));
    return { status: result.status, stdout: result.stdout, log: json.at(-1) };
  };
  const outbox = () => (existsSync(join(state, 'outbox')) ? readdirSync(join(state, 'outbox')).filter((name) => name.endsWith('.json'))
    .map((name) => JSON.parse(readFileSync(join(state, 'outbox', name), 'utf8'))) : []);
  const snapshot = () => {
    const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((item) => (item.isDirectory()
      ? walk(join(dir, item.name)) : [`${relative(state, join(dir, item.name))}:${statSync(join(dir, item.name)).mtimeMs}`]));
    return walk(state).sort();
  };
  return { state, store, run, outbox, snapshot, secrets, outputs };
}

test('CLI: disabled, dry run, send once a day, force, test notice; stdout never carries addresses or secrets', async (t) => {
  const c = await cli(t);
  const before = c.snapshot();
  const disabled = c.run([], { OWNER_DIGEST_ENABLED: '0' });
  assert.equal(disabled.status, 0);
  assert.match(disabled.stdout, /^owner digest disabled\n/);
  assert.deepEqual(disabled.log, { event: 'owner_digest', result: 'disabled' });
  assert.equal(c.run([], { OWNER_NOTIFY_EMAIL: '' }).log.reason, 'no_recipient');
  const dry = c.run(['--dry-run'], { OWNER_DIGEST_VISITORS: '1' });
  assert.equal(dry.status, 0);
  assert.deepEqual(dry.log, { event: 'owner_digest', result: 'dry_run' });
  for (const line of ['FastDog daily summary for 2026-10-19 (Mountain time)', 'Sign-ups: 1 new (1 open, 0 invite); 1 emails verified',
    'Trials: 1 active, 0 ending within 48h, 0 paused', 'Hostnames: unavailable', 'Mail: unavailable',
    'Visitors: 1 page views, 1 unique visitors, 0 bot hits', '  Top pages: / 1']) {
    assert.ok(dry.stdout.split('\n').includes(line), line);
  }
  assert.deepEqual(c.snapshot(), before, 'disabled and dry runs write nothing');
  const sent = c.run();
  assert.equal(sent.status, 0);
  assert.deepEqual(sent.log, { event: 'owner_digest', result: 'sent' });
  assert.deepEqual(c.outbox(), [{ to: OWNER, kind: 'owner-digest' }], 'audit record only, no lines');
  assert.deepEqual(c.store.read('owner_digest'), { last_sent_day: '2026-10-20' });
  const again = c.run();
  assert.deepEqual([again.status, again.log], [0, { event: 'owner_digest', result: 'skipped', reason: 'already_sent' }]);
  assert.equal(c.outbox().length, 1);
  assert.equal(c.run(['--force']).log.result, 'sent');
  assert.equal(c.outbox().length, 2);
  const notice = c.run(['--test-notice'], { OWNER_DIGEST_ENABLED: '' });
  assert.deepEqual([notice.status, notice.log], [0, { event: 'owner_digest', result: 'test_sent' }]);
  assert.deepEqual(c.outbox().map((record) => record.kind).sort(), ['owner-digest', 'owner-digest', 'owner-event']);
  // A held lock skips rather than racing another run.
  writeFileSync(join(c.state, 'owner-digest.lock'), String(process.pid));
  assert.deepEqual(c.run(['--force']).log, { event: 'owner_digest', result: 'skipped', reason: 'locked' });
  writeFileSync(join(c.state, 'owner-digest.lock'), '999999999');
  assert.equal(c.run(['--force']).log.result, 'sent', 'a stale lock is taken over');
  const all = c.outputs.join('\n');
  for (const secret of [OWNER, 'customer@example.com', c.secrets.PORTAL_KEY, c.secrets.SMTP_PASS]) assert.ok(!all.includes(secret));
});

test('CLI: invalid configuration exits 1; an SMTP failure exits 2 without marking the day sent', async (t) => {
  const c = await cli(t);
  for (const [env, reason] of [[{ OWNER_NOTIFY_EMAIL: 'not an address' }, 'invalid_address'], [{ STATE_DIRECTORY: '' }, 'no_state_directory'],
    [{ OWNER_DIGEST_VISITORS: '1', OWNER_DIGEST_SITE_LOGS: '../secret.json' }, 'invalid_site_logs'],
    [{ OWNER_DIGEST_VISITORS: '1', OWNER_DIGEST_FUNNEL_LOG: 'a/b' }, 'invalid_funnel_log'],
    [{ OWNER_DIGEST_VISITORS: '1', OWNER_DIGEST_LOG_DIR: 'relative' }, 'invalid_log_dir'], [{ MAIL_TRANSPORT: 'pigeon' }, 'mail_config']]) {
    const result = c.run([], env);
    assert.deepEqual([result.status, result.log], [1, { event: 'owner_digest', result: 'invalid_config', reason }], reason);
  }
  assert.equal(c.run(['--bogus']).status, 1);
  assert.equal(c.run(['--dry-run', '--test-notice']).status, 1);
  const smtp = { MAIL_TRANSPORT: 'smtp', SMTP_HOST: '127.0.0.1', SMTP_PORT: new URL(await refusedUrl()).port, SMTP_USER: 'digest',
    MAIL_FROM: 'noreply@example.invalid' };
  const failed = c.run([], smtp);
  assert.deepEqual([failed.status, failed.log], [2, { event: 'owner_digest', result: 'failed', reason: 'connect' }]);
  assert.deepEqual(c.outbox(), [{ to: OWNER, kind: 'owner-digest', status: 'failed:connect' }]);
  assert.equal(existsSync(join(c.state, 'owner_digest.json')), false);
  assert.equal(c.run(['--test-notice'], smtp).status, 2);
  const all = c.outputs.join('\n');
  for (const secret of [OWNER, c.secrets.PORTAL_KEY, c.secrets.SMTP_PASS]) assert.ok(!all.includes(secret));
});

// ---- Units ----

function unit(path) {
  const entries = {};
  for (const line of readFileSync(join(root, path), 'utf8').split('\n')) {
    const match = /^([A-Za-z]+)=(.*)$/.exec(line);
    if (match) (entries[match[1]] ||= []).push(match[2]);
  }
  return entries;
}

test('systemd units: capped oneshot as fdportal, 08:00 America/Denver daily, persistent', () => {
  const service = unit('deploy/fastdog-owner-digest.service');
  for (const [key, value] of [['Type', 'oneshot'], ['User', 'fdportal'], ['Group', 'fdportal'], ['Nice', '10'], ['CPUQuota', '20%'],
    ['MemoryMax', '96M'], ['IOSchedulingClass', 'idle'], ['StateDirectory', 'fastdog-portal'], ['StateDirectoryMode', '0700'],
    ['ProtectSystem', 'strict'], ['NoNewPrivileges', 'yes'], ['EnvironmentFile', '/etc/fastdog/portal.env']]) {
    assert.deepEqual(service[key], [value], key);
  }
  assert.match(service.ExecStart[0], /^\/usr\/bin\/node .*portal\/bin\/owner-digest\.js$/);
  const timer = unit('deploy/fastdog-owner-digest.timer');
  assert.deepEqual(timer.OnCalendar, ['*-*-* 08:00:00 America/Denver']);
  assert.deepEqual(timer.Persistent, ['true']);
  assert.deepEqual(timer.Unit, ['fastdog-owner-digest.service']);
  assert.deepEqual(timer.WantedBy, ['timers.target']);
});
