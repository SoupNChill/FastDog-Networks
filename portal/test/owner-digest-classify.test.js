import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { temporary } from './helpers.js';
import { digestConfig } from '../bin/owner-digest.js';
import { collectAccounts, countVisitors, countFunnel, PROBE_PATH, PROBE_CATEGORIES, SHADOW_CAP, readShadow, BOT_UA, renderDigest } from '../src/owner-digest.js';
const window = { start: 1000, end: 3000 };
const created_at = new Date(2000).toISOString();
// Synthetic non-reserved suffix: no real customer address or DNS lookup.
const domain = ['example', 'customer'].join('.');
const config = (extra = {}) => digestConfig({ STATE_DIRECTORY: '.', OWNER_NOTIFY_EMAIL: `owner@${domain}`, ...extra });

test('internal tenants exclude all their users and trials, but retain hostname inventory', () => {
  const emails = [`owner@${domain}`, `OWNER+tag@${domain}`, 'review@example.test', `exact@${domain}`, `flag@${domain}`, `customer@${domain}`];
  const tenants = emails.map((_, i) => ({ id: `t_${i}`, created_at, plan: 'trial', source: 'open', ...(i === 4 ? { internal: true } : {}) }));
  const users = emails.map((email, i) => ({ tenant_id: `t_${i}`, email, email_verified_at: created_at }));
  users.push({ tenant_id: 't_0', email: `second@${domain}`, email_verified_at: created_at });
  const store = { read: (name, fallback) => name === 'accounts' ? { tenants, users } : fallback };
  const cfg = config({ OWNER_DIGEST_INTERNAL_EMAILS: ` EXACT@${domain.toUpperCase()},bad, @example.test` });
  assert.deepEqual(cfg.internalEmails, [`exact@${domain}`]);
  const result = collectAccounts({ store, now: 2500, window, config: cfg });
  assert.deepEqual(result.internal, { tenants: 5, signups: 5 });
  assert.deepEqual(result.accounts, { available: true, signups: 1, signups_open: 1, signups_invite: 0, verified_in_window: 1, tenants: 1, users: 1, verified: 1, suspended: 0 });
  assert.equal(result.trials.active, 1);
  assert.equal(result.tenants.length, 6);
  const lines = renderDigest(result);
  assert.equal(lines[lines.findIndex((s) => s.startsWith('  Totals:')) + 1], '  Internal/test: 5 accounts (excluded above)');
  assert.ok(!lines.join('\n').includes('@'));
  const disabled = collectAccounts({ store, now: 2500, window, config: { ...cfg, internalAuto: false } });
  assert.equal(disabled.internal.tenants, 2);
  assert.equal(config({ OWNER_DIGEST_INTERNAL_AUTO: '0' }).internalAuto, false);
  tenants[4].internal = false;
  const none = collectAccounts({ store, now: 2500, window, config: { internalAuto: false } });
  assert.ok(!renderDigest(none).some((s) => s.includes('Internal/test')));
  for (const target of [tenants[5], users[5]]) for (const flag of ['test', 'internal']) {
    target[flag] = true;
    assert.equal(collectAccounts({ store, now: 2500, window, config: { internalAuto: false } }).internal.tenants, 1);
    delete target[flag];
  }
});

const probes = ['/phpinfo', '/_profiler/phpinfo', '/.aws/config', '/.env', '/.env.local', '/wp-login.php', '/wp-login.php/extra', '/xmlrpc.php', '/cgi-bin/x', '/index.php', '/.git/config', '/.ssh/x', '/.svn/x', '/.hg/x', '/.DS_Store', '/php-info', '/phpmyadmin', '/pma', '/wp-admin', '/wp-content/a', '/wp-includes/a', '/actuator', '/server-status', '/vendor/phpunit/x', '/x/config.json', '/config.yml', '/x/config.yaml', ...['asp', 'aspx', 'jsp', 'cgi', 'bak', 'sql', 'zip', 'tar', 'gz', 'old', 'swp'].map((ext) => `/x.${ext}`)];
test('probe and UA patterns include scanners without flagging ordinary routes', () => {
  for (const path of probes) assert.ok(PROBE_PATH.test(path), path);
  for (const path of ['/', '/pricing/', '/docs/getting-started', '/login', '/admin', '/.well-known/security.txt']) assert.ok(!PROBE_PATH.test(path), path);
  for (const ua of ['zgrab', 'masscan', 'nmap', 'nikto', 'sqlmap', 'httpx', 'okhttp', 'libwww', 'java/1', 'axios', 'node-fetch', 'scrapy', 'censys', 'expanse', 'l9explore', 'nuclei', 'wpscan']) assert.ok(BOT_UA.test(ua), ua);
});
const row = (uri = '/', user_agent = 'Mozilla/5.0', extra = {}) => ({ ts: 2, request: { client_ip: '203.0.113.0', method: 'GET', uri }, status: 200, user_agent, ...extra });
test('masked and legacy logs, NUL padding, empty UA, failed probes and human-only funnel', async (t) => {
  const file = join(temporary(t), 'access.json');
  const old = row('/old', 'Googlebot');
  old.request = { remote_ip: '198.51.100.5', method: 'GET', uri: '/old', headers: { 'User-Agent': ['Mozilla/5.0'] } };
  const entries = [row(), row('/bot', 'Googlebot'), row('/empty', ''), old, row('/signup'), row('/signup', ''), row('/signup', 'Googlebot'), ...probes.map((p) => row(p, 'Mozilla/5.0', { status: 404 }))];
  entries.push(row('/phpinfo', 'Mozilla/5.0', { request: { method: 'POST', uri: '/phpinfo' }, status: 500 }));
  writeFileSync(file, '\0'.repeat(100000) + entries.map(JSON.stringify).join('\n'));
  const result = await countVisitors({ files: [file], window });
  assert.equal(result.page_views, 3);
  assert.equal(result.bot_hits, 4);
  assert.equal(result.probe_hits, probes.length + 1);
  assert.equal(result.unique_visitors, 2);
  assert.ok(result.top_paths.every(([p]) => !PROBE_PATH.test(p)));
  assert.equal(result.shadow_join, 'off');
  assert.equal((await countFunnel({ files: [file], window })).signup_views, 1);
  assert.ok(!JSON.stringify(result).includes('Mozilla'));
});

test('shadow join is windowed, NUL-tolerant, optional and fails open', async (t) => {
  const dir = temporary(t), file = join(dir, 'access.json'), shadowFile = join(dir, 'shadow.jsonl');
  writeFileSync(file, [row('/signup'), row('/allowed'), row('/outside')].map(JSON.stringify).join('\n'));
  const shadow = (path, action, ts = created_at) => ({ ts, path, action, ip_prefix: '203.0.113.0/24' });
  writeFileSync(shadowFile, '\0'.repeat(10000) + [shadow('/signup', 'challenge'), shadow('/allowed', 'allow'), shadow('/outside', 'block', new Date(window.end).toISOString()), 'junk'].map(JSON.stringify).join('\n'));
  const result = await countVisitors({ files: [file], window, shadowFile });
  assert.equal(result.shadow_join, 'on');
  assert.equal(result.bot_hits, 1);
  assert.equal(result.page_views, 2);
  assert.equal((await countFunnel({ files: [file], window, shadowFile })).signup_views, 0);
  const missing = await countVisitors({ files: [file], window, shadowFile: join(dir, 'missing') });
  assert.equal(missing.shadow_join, 'unavailable');
  assert.equal(missing.page_views, 3);
  assert.equal(config({ OWNER_DIGEST_SHADOW_FILE: 'relative' }).error, 'invalid_shadow_file');
  assert.equal(config({ OWNER_DIGEST_SHADOW_FILE: shadowFile }).shadowFile, shadowFile);
});

test('reserved domains match only whole suffixes; internal suspensions and paused trials stay excluded', () => {
  const domains = ['test', 'example', 'invalid', 'localhost', 'example.com', 'example.net', 'example.org'];
  const users = domains.map((suffix, i) => ({ tenant_id: `t_${i}`, email: `review@sub.${suffix}` }));
  const tenants = users.map((user) => ({ id: user.tenant_id, created_at }));
  const store = { read: (name, fallback) => ({ accounts: { tenants, users },
    trials: { tenants: { t_0: { paused_at: created_at } } },
    suspensions: { tenants: { t_1: { at: created_at, reason: 'test', revoked_before: 0 } } } }[name] || fallback) };
  const result = collectAccounts({ store, now: 2500, window });
  assert.equal(result.internal.tenants, 7);
  assert.equal(result.accounts.suspended, 0);
  assert.deepEqual(result.trials.paused, []);
  assert.equal(result.tenants.length, 6);
  assert.equal(result.tenants.find((tenant) => tenant.id === 't_0').paused, true);
});


test('shadow keys have fixed size, skip long paths and stop at the cap', async (t) => {
  const file = join(temporary(t), 'shadow.jsonl');
  const shadow = (path) => JSON.stringify({ ts: 2, path, action: 'block', ip_prefix: '203.0.113.0/24' }) + '\n';
  writeFileSync(file, shadow('/' + 'x'.repeat(2048)));
  const skipped = await readShadow(file, window, 'test-salt');
  assert.equal(skipped.keys.size, 0);
  assert.equal(skipped.status, 'partial');
  for (let i = 0; i < SHADOW_CAP + 100; i += 100) {
    appendFileSync(file, Array.from({ length: 100 }, (_, j) => shadow('/' + 'x'.repeat(1800) + (i + j))).join(''));
  }
  const result = await readShadow(file, window, 'test-salt');
  assert.equal(result.keys.size, SHADOW_CAP);
  assert.equal(result.status, 'partial');
  assert.ok([...result.keys].every((key) => /^[A-Za-z0-9+/]{22}$/.test(key)));
  const visitors = await countVisitors({ files: [], window, shadowFile: file });
  assert.equal(visitors.shadow_join, 'partial');
});

test('decoded probes use finite categories and never render request identifiers', async (t) => {
  const dir = temporary(t), file = join(dir, 'access.json'), shadowFile = join(dir, 'shadow.jsonl');
  const token = 'abcdef0123456789'.repeat(12);
  const sensitive = ['/.env/203.0.113.7', '/.git/' + token];
  writeFileSync(file, [...sensitive, '/%2eenv', '/%2Egit/config', '/wp%2dlogin.php', '/%E0%A4%A',
    '//docs//%67uide', '/%73ignup'].map((path) => row(path)).concat(row('/crawler-page', 'Googlebot')).map(JSON.stringify).join('\n'));
  writeFileSync(shadowFile, JSON.stringify({ ts: 2, path: '//sign%75p', action: 'block', ip_prefix: '203.0.113.0/24' }));
  const result = await countVisitors({ files: [file], window, shadowFile });
  assert.equal(result.page_views, 1);
  assert.deepEqual(result.top_paths, [['/docs/guide', 1]]);
  assert.equal(result.probe_hits, 5);
  assert.deepEqual(result.probe_categories, [['.env', 2], ['.git', 2], ['wp-login', 1]]);
  assert.ok(result.probe_categories.every(([label]) => PROBE_CATEGORIES.some(([fixed]) => fixed === label)));
  assert.equal(result.bot_hits, 5);
  assert.equal((await countFunnel({ files: [file], window, shadowFile })).signup_views, 0);
  const lines = renderDigest({ visitors: result });
  assert.ok(lines.includes('  Top probe types: .env 2, .git 2, wp-login 1'));
  for (const value of [...sensitive, '203.0.113.7', token, 'crawler-page']) assert.ok(!lines.join('\n').includes(value));
  assert.equal('bot_top_paths' in result, false);
});
