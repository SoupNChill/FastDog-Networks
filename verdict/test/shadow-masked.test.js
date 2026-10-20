import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isIP } from 'node:net';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scoreAccessLogLine } from '../src/shadow/score.js';
import { localHeuristic } from '../src/engine/heuristic.js';

// Each test uses its own documentation-range IPs/prefixes so the module-level velocity maps never collide.
const CHROME = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36';
const HEADERS = { 'User-Agent': [CHROME], Accept: ['text/html'], 'Accept-Language': ['en-US,en;q=0.9'] };
const opts = { verifyBot: () => null };
const unmasked = (ip, uri, headers) => JSON.stringify({ ts: 1792535152.64, request: { remote_ip: ip, client_ip: ip, method: 'GET', host: 'fastdognetworks.com', uri, headers } });
const masked = (prefix, uri, ua) => JSON.stringify({ level: 'info', ts: 1792535152.64, logger: 'http.log.access.log3', msg: 'handled request',
  request: { client_ip: prefix, method: 'GET', host: 'fastdognetworks.com', uri }, duration: 0.001, status: 200, user_agent: ua });
const pick = r => ({ action: r.action, score: r.score, reasons: r.reasons });
const notRawIp = r => assert.ok(r.ip_prefix === null || (!isIP(r.ip_prefix) && /\/(24|64)$/.test(r.ip_prefix)), r.ip_prefix);

test('masked browser line: UA read from user_agent, no header or velocity signals, allow', () => {
  let r;
  for (let i = 0; i < 40; i++) r = scoreAccessLogLine(masked('198.51.100.0', '/', CHROME), opts);
  assert.equal(r.ua, CHROME);
  assert.deepEqual(pick(r), { action: 'allow', score: 0.2, reasons: [] });
  assert.equal(r.ip_prefix, '198.51.100.0/24');
  notRawIp(r);
});

test('masked line with automation UAs still fires UA signals', () => {
  const sqlmap = scoreAccessLogLine(masked('198.51.101.0', '/', 'sqlmap/1.7'), opts);
  assert.deepEqual(sqlmap.reasons, ['malicious_tool']);
  assert.equal(sqlmap.action, 'block');
  const headless = scoreAccessLogLine(masked('198.51.102.0', '/', 'Mozilla/5.0 HeadlessChrome/129.0.0.0'), opts);
  assert.deepEqual(headless.reasons, ['headless_automation']);
  assert.equal(headless.action, 'challenge');
});

test('masked line with a probe path still fires probe_path', () => {
  const r = scoreAccessLogLine(masked('198.51.103.0', '/wp-login.php', CHROME), opts);
  assert.deepEqual(pick(r), { action: 'block', score: 0.75, reasons: ['probe_path'] });
});

test('masked IPv6 /48 line never persists a raw address', () => {
  const r = scoreAccessLogLine(masked('2001:db8:1::', '/', CHROME), opts);
  assert.equal(r.ip_prefix, '2001:0db8:0001:0000::/64');
  notRawIp(r);
});

// Expected values captured from the 0.3.2 scorer before this change.
test('unmasked lines score exactly as before', () => {
  const cases = [
    ['192.0.2.10', '/', HEADERS, { action: 'allow', score: 0.2, reasons: [] }, CHROME, '192.0.2.0/24'],
    ['192.0.2.11', '/wp-login.php', HEADERS, { action: 'block', score: 0.75, reasons: ['probe_path'] }, CHROME, '192.0.2.0/24'],
    ['192.0.2.12', '/', { 'User-Agent': ['sqlmap/1.7'] }, { action: 'block', score: 0.85, reasons: ['malicious_tool', 'missing_accept_language'] }, 'sqlmap/1.7', '192.0.2.0/24'],
    ['2001:db8:5::7', '/', HEADERS, { action: 'allow', score: 0.2, reasons: [] }, CHROME, '2001:0db8:0005:0000::/64'],
  ];
  for (const [ip, uri, headers, expected, ua, prefix] of cases) {
    const r = scoreAccessLogLine(unmasked(ip, uri, headers), opts);
    assert.deepEqual(pick(r), expected, ip);
    assert.equal(r.ua, ua);
    assert.equal(r.ip_prefix, prefix);
    notRawIp(r);
  }
});

test('unmasked line with an empty headers object still fires missing_accept_language', () => {
  const r = scoreAccessLogLine(unmasked('192.0.2.13', '/', {}), opts);
  assert.deepEqual(pick(r), { action: 'allow', score: 0.3, reasons: ['missing_accept_language'] });
  assert.equal(r.ua, '');
});

test('unmasked lines from one full IP still fire ip_velocity past 30', () => {
  let r;
  for (let i = 0; i < 30; i++) r = scoreAccessLogLine(unmasked('192.0.2.50', '/', HEADERS), opts);
  assert.ok(!r.reasons.includes('ip_velocity'));
  r = scoreAccessLogLine(unmasked('192.0.2.50', '/', HEADERS), opts);
  assert.ok(r.reasons.includes('ip_velocity'));
  notRawIp(r);
});

test('masked-replay.mjs scores only unmasked lines, per mode, and prints counts only', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'vmr-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const log = join(dir, 'access.json');
  const lines = [];
  // No Accept-Language: raw scores missing_accept_language + ip_velocity (challenge) after 30; masked knows neither.
  for (let i = 0; i < 35; i++) lines.push(unmasked('192.0.2.200', '/?q=1', { 'User-Agent': [CHROME], Accept: ['text/html'] }));
  lines.push(unmasked('192.0.2.201', '/', { 'User-Agent': ['sqlmap/1.7'], 'Accept-Language': ['en'] }));
  lines.push(masked('198.51.104.0', '/', CHROME), 'not json', '');
  writeFileSync(log, lines.join('\n'));
  const script = join(dirname(fileURLToPath(import.meta.url)), '../scripts/masked-replay.mjs');
  const run = (mode, max) => execFileSync(process.execPath, [script, mode, String(max), log], { cwd: dir, encoding: 'utf8' });
  const raw = run('raw', 1000);
  assert.deepEqual(JSON.parse(raw), { mode: 'raw', scored: 36, actions: { allow: 30, challenge: 5, block: 1 } });
  const out = run('masked', 1000);
  assert.deepEqual(JSON.parse(out), { mode: 'masked', scored: 36, actions: { allow: 35, challenge: 0, block: 1 } });
  assert.deepEqual(JSON.parse(run('masked', 2)), { mode: 'masked', scored: 2, actions: { allow: 1, challenge: 0, block: 1 } });
  for (const text of [raw, out]) assert.ok(!/192\.0\.2|Mozilla|sqlmap/.test(text));
});

test('heuristic default is unchanged without the opt-out field; ip_velocity: false skips only the IP rate', () => {
  const now = Date.now();
  let on, off;
  for (let i = 0; i < 31; i++) {
    on = localHeuristic({ ip: '203.0.113.77', path: '/' }, { now });
    off = localHeuristic({ ip: '203.0.113.78', path: '/', ip_velocity: false }, { now });
  }
  assert.deepEqual(on.reasons, ['ip_velocity']);
  assert.deepEqual(off.reasons, []);
});
