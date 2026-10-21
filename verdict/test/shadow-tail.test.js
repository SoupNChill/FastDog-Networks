import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scoreAccessLogLine } from '../src/shadow/score.js';
import { buildShadowSummary } from '../src/shadow/summary.js';
import { cleanLine } from '../src/shadow/lines.js';
import { consumeLog, loadOffsets, offsetsFile, resumeOffset, saveOffsets } from '../src/shadow/offsets.js';
import { DEMO_HOST, ipPrefix } from '../src/edge/security.js';
import { ipBucketKey } from '../src/middleware/rateLimit.js';

// Synthetic data only: documentation-range IPs, the demo host, and IPs not used by other test files.
const scripts = join(dirname(fileURLToPath(import.meta.url)), '../scripts');
const CHROME = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36';
const HEADERS = { 'User-Agent': [CHROME], Accept: ['text/html'], 'Accept-Language': ['en-US,en;q=0.9'] };
const opts = { verifyBot: () => null };
const nowTs = () => Date.now() / 1000;
const unmasked = (ip, uri, ts = nowTs()) => JSON.stringify({ ts, request: { remote_ip: ip, client_ip: ip, method: 'GET', host: DEMO_HOST, uri, headers: HEADERS } });
const masked = (prefix, uri, ts = nowTs()) => JSON.stringify({ level: 'info', ts, msg: 'handled request',
  request: { client_ip: prefix, method: 'GET', host: DEMO_HOST, uri }, status: 200, user_agent: CHROME });
const tempDir = (t, prefix) => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function waitFor(fn, what, ms = 15000) {
  const end = Date.now() + ms;
  for (;;) {
    const value = fn();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`);
    await sleep(50);
  }
}
const readRows = file => existsSync(file) ? readFileSync(file, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)) : [];

// --- 0. NUL bytes ---------------------------------------------------------------------------

test('cleanLine strips NUL bytes and a trailing CR; NUL-only lines become empty', () => {
  assert.equal(cleanLine('\0\0\0{"a":1}'), '{"a":1}');
  assert.equal(cleanLine('\0'.repeat(1000)), '');
  assert.equal(cleanLine('{"a":1}\r'), '{"a":1}');
  assert.equal(cleanLine('{"a":1}'), '{"a":1}');
  assert.equal(cleanLine(undefined), '');
});

test('consumeLog: a 600000-byte NUL hole before a masked and a normal line yields 2 rows; offset passes the hole', async (t) => {
  const dir = tempDir(t, 'vnul-');
  const log = join(dir, 'access.json');
  writeFileSync(log, Buffer.concat([Buffer.alloc(600000), Buffer.from(masked('198.51.110.0', '/') + '\n' + unmasked('192.0.2.110', '/') + '\n' + '\0'.repeat(10) + '\n')]));
  const size = statSync(log).size;
  const rows = [];
  const next = await consumeLog(log, { ino: statSync(log).ino, offset: 0 }, async line => {
    const r = await scoreAccessLogLine(line, opts);
    if (r) rows.push(r);
  });
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map(r => r.ip_prefix), ['198.51.110.0/24', '192.0.2.0/24']);
  assert.deepEqual(next, { ino: statSync(log).ino, offset: size });
  assert.ok(next.offset > 600000);
  let again = 0;
  assert.deepEqual(await consumeLog(log, next, () => { again++; }), next);
  assert.equal(again, 0);
});

test('consumeLog leaves a line still being written for the next poll (never scored twice or in halves)', async (t) => {
  const dir = tempDir(t, 'vpart-');
  const log = join(dir, 'access.json');
  const full = unmasked('192.0.2.111', '/');
  writeFileSync(log, full + '\n' + full.slice(0, 20));
  const seen = [];
  const first = await consumeLog(log, { ino: statSync(log).ino, offset: 0 }, line => { seen.push(line); });
  assert.deepEqual(seen, [full]);
  assert.equal(first.offset, Buffer.byteLength(full) + 1);
  appendFileSync(log, full.slice(20) + '\n');
  const second = await consumeLog(log, first, line => { seen.push(line); });
  assert.deepEqual(seen, [full, full]);
  assert.equal(second.offset, statSync(log).size);
  await assert.rejects(consumeLog(join(dir, 'missing.json'), undefined, () => {}), { code: 'ENOENT' });
});

test('scoreAccessLogLine returns null for JSON that is not an object', () => {
  for (const line of ['null', '0', '"x"', 'true']) assert.equal(scoreAccessLogLine(line, opts), null);
});

// --- 1. IPv6 /48 for stored shadow rows only -------------------------------------------------

test('ipPrefix default is unchanged; v6Bits: 48 is opt-in; IPv4 stays /24', () => {
  assert.equal(ipPrefix('2001:db8:abcd:12::1'), '2001:0db8:abcd:0012::/64');
  assert.equal(ipPrefix('2001:db8:abcd:12::1', { v6Bits: 48 }), '2001:0db8:abcd::/48');
  assert.equal(ipPrefix('192.0.2.7'), '192.0.2.0/24');
  assert.equal(ipPrefix('192.0.2.7', { v6Bits: 48 }), '192.0.2.0/24');
  assert.equal(ipPrefix('::ffff:192.0.2.7', { v6Bits: 48 }), '192.0.2.0/24');
  assert.equal(ipPrefix('not-an-ip', { v6Bits: 48 }), null);
});

test('rate-limit buckets keep /64 granularity', () => {
  assert.equal(ipBucketKey('2001:db8:abcd:12::1'), '2001:0db8:abcd:0012::/64');
  assert.notEqual(ipBucketKey('2001:db8:abcd:12::1'), ipBucketKey('2001:db8:abcd:13::1'));
  assert.equal(ipBucketKey('192.0.2.7'), '192.0.2.0/24');
});

test('shadow row ip_prefix for an IPv6 client is the /48', () => {
  assert.equal(scoreAccessLogLine(unmasked('2001:db8:abcd:12::1', '/'), opts).ip_prefix, '2001:0db8:abcd::/48');
  assert.equal(scoreAccessLogLine(masked('2001:db8:abce::', '/'), opts).ip_prefix, '2001:0db8:abce::/48');
});

// --- 2. Query strings never persisted --------------------------------------------------------

test('shadow rows persist the path without the query; scoring still sees the full uri', () => {
  const r = scoreAccessLogLine(unmasked('192.0.2.120', '/wp-login.php?redirect=secret-token'), opts);
  assert.equal(r.path, '/wp-login.php');
  assert.deepEqual(r.reasons, ['probe_path']);
  assert.ok(!JSON.stringify(r).includes('secret-token'));
});

test('daily summary strips query strings from samples built from older rows', async (t) => {
  const dir = tempDir(t, 'vsum-');
  const file = join(dir, 'shadow.jsonl');
  const day = '2026-10-20';
  const row = (path, action) => JSON.stringify({ ts: `${day}T01:00:00.000Z`, host: DEMO_HOST, ip_prefix: '192.0.2.0/24', path, method: 'GET', ua: 'curl/8', action, reason: 'probe_path', reasons: ['probe_path'], score: 0.75 });
  writeFileSync(file, [row('/a?token=secret-token', 'block'), row('/b', 'challenge'), row('/c?x=1', 'allow')].join('\n') + '\n');
  const summary = await buildShadowSummary(file, { day });
  assert.deepEqual(summary.samples_would_challenge_or_block.map(s => s.path), ['/a', '/b']);
  assert.ok(!JSON.stringify(summary).includes('secret-token'));
});

// --- 3. Persisted offsets --------------------------------------------------------------------

test('resumeOffset: resume, start at end when unseen, 0 on rotation or truncation', () => {
  assert.equal(resumeOffset({ ino: 7, offset: 100 }, { ino: 7, size: 150 }), 100); // resume
  assert.equal(resumeOffset({ ino: 7, offset: 100 }, { ino: 7, size: 100 }), 100); // nothing new
  assert.equal(resumeOffset(undefined, { ino: 7, size: 150 }), 150); // never seen: no history rescan
  assert.equal(resumeOffset({ ino: 7, offset: 100 }, { ino: 8, size: 150 }), 0); // rotated
  assert.equal(resumeOffset({ ino: 7, offset: 100 }, { ino: 8, size: 50 }), 0);
  assert.equal(resumeOffset({ ino: 7, offset: 100 }, { ino: 7, size: 40 }), 0); // truncated
  assert.equal(resumeOffset({ ino: null, offset: 0 }, { ino: 7, size: 150 }), 0); // appeared after start
  assert.equal(resumeOffset({ ino: 7 }, { ino: 7, size: 150 }), 150); // malformed entry: treat as unseen
});

test('offsetsFile defaults next to the shadow file and honours the override', () => {
  assert.equal(offsetsFile({ VERDICT_SHADOW_FILE: '/opt/verdict/data/shadow.jsonl' }), '/opt/verdict/data/shadow-offsets.json');
  assert.equal(offsetsFile({}), join('data', 'shadow-offsets.json'));
  assert.equal(offsetsFile({ VERDICT_SHADOW_FILE: '/x/s.jsonl', VERDICT_SHADOW_OFFSETS_FILE: '/y/o.json' }), '/y/o.json');
});

test('saveOffsets writes atomically with mode 0600; loadOffsets tolerates missing or corrupt state', async (t) => {
  const dir = tempDir(t, 'voff-');
  const file = join(dir, 'sub', 'shadow-offsets.json');
  assert.deepEqual(await loadOffsets(file), {});
  const state = { '/var/log/a.json': { ino: 12, offset: 345 } };
  await saveOffsets(file, state);
  assert.deepEqual(await loadOffsets(file), state);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(join(dir, 'sub')), ['shadow-offsets.json']);
  writeFileSync(file, '{not json');
  assert.deepEqual(await loadOffsets(file), {});
  writeFileSync(file, '[1]');
  assert.deepEqual(await loadOffsets(file), {});
});

test('shadow-tail.js starts unseen logs at the end and resumes after a restart without replaying', async (t) => {
  const dir = tempDir(t, 'vtail-');
  const log = join(dir, 'access.json');
  const out = join(dir, 'data', 'shadow.jsonl');
  const state = join(dir, 'data', 'shadow-offsets.json');
  writeFileSync(log, unmasked('192.0.2.130', '/old-1') + '\n' + unmasked('192.0.2.130', '/old-2') + '\n');
  const env = { VERDICT_SHADOW_LOGS: log, VERDICT_SHADOW_FILE: out, VERDICT_SHADOW_POLL_MS: '500', VERDICT_ASN_FILE: '' };
  if (process.env.NODE_OPTIONS) env.NODE_OPTIONS = process.env.NODE_OPTIONS;
  const savedOffset = () => { try { return JSON.parse(readFileSync(state, 'utf8'))[log]?.offset; } catch { return undefined; } };
  const start = () => {
    const child = spawn(process.execPath, [join(scripts, 'shadow-tail.js')], { env, stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', d => { stderr += d; });
    const exited = new Promise(r => child.on('exit', r));
    t.after(() => child.kill('SIGKILL'));
    return { stop: async () => { child.kill('SIGTERM'); await exited; return stderr; } };
  };

  let tail = start();
  await waitFor(() => savedOffset() === statSync(log).size, 'initial offsets');
  assert.deepEqual(readRows(out), []); // history not rescanned
  appendFileSync(log, unmasked('192.0.2.130', '/new-1') + '\n');
  await waitFor(() => savedOffset() === statSync(log).size, 'offset after append');
  assert.deepEqual(readRows(out).map(r => r.path), ['/new-1']);
  assert.equal(statSync(state).mode & 0o777, 0o600);
  assert.equal(await tail.stop(), '');

  appendFileSync(log, unmasked('192.0.2.130', '/new-2?q=1') + '\n'); // written while stopped
  tail = start();
  await waitFor(() => savedOffset() === statSync(log).size, 'offset after restart');
  await sleep(600); // one more poll: nothing re-read
  assert.deepEqual(readRows(out).map(r => r.path), ['/new-1', '/new-2']);

  writeFileSync(log, unmasked('192.0.2.130', '/after-truncate') + '\n'); // same inode, smaller
  await waitFor(() => readRows(out).length === 3, 'row after truncation');
  assert.equal(readRows(out)[2].path, '/after-truncate');
  assert.equal(await tail.stop(), '');
});

// --- masked-replay.mjs asis ------------------------------------------------------------------

test('masked-replay.mjs asis scores every line as it is (NUL-prefixed too) and prints counts only', (t) => {
  const dir = tempDir(t, 'vasis-');
  const log = join(dir, 'access.json');
  const lines = [masked('198.51.111.0', '/'), masked('198.51.112.0', '/wp-login.php'), '\0'.repeat(5000) + masked('198.51.113.0', '/'),
    unmasked('192.0.2.140', '/'), '\0\0\0', 'not json', 'null', ''];
  writeFileSync(log, lines.join('\n'));
  const run = mode => execFileSync(process.execPath, [join(scripts, 'masked-replay.mjs'), mode, '1000', log], { cwd: dir, encoding: 'utf8' });
  const asis = run('asis');
  assert.deepEqual(JSON.parse(asis), { mode: 'asis', scored: 4, actions: { allow: 3, challenge: 0, block: 1 } });
  assert.deepEqual(JSON.parse(run('raw')).scored, 1); // raw|masked unchanged: only lines with request.headers
  assert.ok(!/198\.51|192\.0\.2|Mozilla|wp-login/.test(asis));
});

// --- 4. shadow-cleanup.mjs -------------------------------------------------------------------

function cleanupFixture(t) {
  const dir = tempDir(t, 'vclean-');
  const shadow = join(dir, 'shadow.jsonl');
  const ts = i => new Date(Date.UTC(2026, 9, 20, 0, 0, i)).toISOString();
  const row = (i, extra = {}) => ({ ts: ts(i), host: DEMO_HOST, ip_prefix: '198.51.120.0/24', path: `/p${i}${i % 10 === 0 && i < 100 ? '?token=secret-token' : ''}`,
    method: 'GET', ua: 'curl/8', action: 'allow', reasons: [], score: 0.2, ...extra });
  const lines = [];
  // Original rows, one with non-canonical spacing so a re-serialisation would be visible.
  lines.push(`{"ts": "${ts(1000)}", "host": "${DEMO_HOST}", "path": "/spaced", "method": "GET", "ip_prefix": null}`);
  for (let i = 0; i < 60; i++) lines.push(JSON.stringify(row(i)));
  lines.push(JSON.stringify(row(500)), JSON.stringify(row(501)));
  // Re-scan block 1: 60 copies, re-scored with a different UA/score (must still count as duplicates).
  for (let i = 0; i < 60; i++) lines.push(JSON.stringify(row(i, { ua: CHROME, score: 0.3, path: `/p${i}` })));
  lines.push(JSON.stringify(row(502)));
  // A genuine burst: 2 isolated duplicates, never dropped.
  lines.push(JSON.stringify(row(500)), JSON.stringify(row(501)));
  lines.push('\0'.repeat(64));
  // Re-scan block 2: 55 copies.
  for (let i = 0; i < 55; i++) lines.push(JSON.stringify(row(i)));
  lines.push(JSON.stringify(row(503)));
  writeFileSync(shadow, lines.join('\n') + '\n', { mode: 0o600 });
  const summaries = join(dir, 'summaries');
  mkdirSync(summaries);
  const dirty = { day: '2026-10-20', counts: { allow: 1, challenge: 0, block: 1, total: 2 }, top_reasons: [{ reason: 'probe_path', count: 1 }],
    samples_would_challenge_or_block: [{ ts: ts(1), host: DEMO_HOST, path: '/a?token=secret-token', method: 'GET' }, { ts: ts(2), host: DEMO_HOST, path: '/b?x=1' }, { path: '/c' }] };
  const clean = { day: '2026-10-19', samples_would_challenge_or_block: [{ path: '/d' }] };
  writeFileSync(join(summaries, 'shadow-summary-20261020.json'), JSON.stringify(dirty, null, 2));
  writeFileSync(join(summaries, 'shadow-summary-20261019.json'), JSON.stringify(clean, null, 2));
  writeFileSync(join(summaries, 'other.json'), JSON.stringify({ path: '/e?x=1' }));
  return { dir, shadow, summaries, lines, dirty, clean };
}
const cleanup = (...args) => spawnSync(process.execPath, [join(scripts, 'shadow-cleanup.mjs'), ...args], { encoding: 'utf8' });
const old = file => { const past = new Date(Date.now() - 60000); utimesSync(file, past, past); };

test('shadow-cleanup.mjs plan reports counts only and finds re-scan runs of >= 50 duplicates', (t) => {
  const f = cleanupFixture(t);
  const before = readFileSync(f.shadow, 'utf8');
  const res = cleanup('plan', f.shadow, f.summaries);
  assert.equal(res.status, 0, res.stderr);
  const plan = JSON.parse(res.stdout);
  assert.equal(plan.rows, 1 + 60 + 2 + 60 + 1 + 2 + 55 + 1);
  assert.equal(plan.rows_with_query, 6 + 6); // /p0../p50 in the originals and in block 2 (block 1 has none)
  assert.equal(plan.lines_cleaned, 1);
  assert.equal(plan.dedupe, 'latest');
  assert.deepEqual(plan.dup_runs.map(r => [r.start_index, r.end_index, r.count]), [[63, 122, 60], [127, 181, 55]]);
  assert.equal(plan.dup_runs[0].first_ts, '2026-10-20T00:00:00.000Z');
  assert.equal(plan.dup_runs[1].last_ts, '2026-10-20T00:00:54.000Z');
  assert.equal(plan.would_drop, 55);
  assert.deepEqual(plan.summaries_with_query, ['shadow-summary-20261020.json']);
  assert.equal(plan.summary_paths_changed, 2);
  assert.equal(plan.applied, undefined);
  assert.ok(!/198\.51|curl|Mozilla|\/p\d|secret|\/spaced/.test(res.stdout));
  assert.equal(readFileSync(f.shadow, 'utf8'), before); // plan never writes
  assert.equal(JSON.parse(cleanup('plan', f.shadow, f.summaries, '--dedupe', 'all').stdout).would_drop, 115);
});

test('shadow-cleanup.mjs apply rewrites atomically, keeps untouched rows byte-identical, refuses a fresh file', (t) => {
  const f = cleanupFixture(t);
  const refused = cleanup('apply', f.shadow, f.summaries);
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /tailer/);
  old(f.shadow);
  const res = cleanup('apply', f.shadow, f.summaries, '--dedupe', 'all');
  assert.equal(res.status, 0, res.stderr);
  const result = JSON.parse(res.stdout);
  assert.equal(result.applied, true);
  assert.equal(result.would_drop, 115);

  const after = readFileSync(f.shadow, 'utf8').split('\n');
  assert.equal(after.pop(), '');
  assert.equal(after.length, f.lines.length - 115 - 1);
  assert.equal(after[0], f.lines[0]); // untouched row: exact bytes
  assert.equal(after[2], f.lines[2]);
  assert.ok(!after.some(l => l.includes('?') || l.includes('\0')));
  const rows = after.map(l => JSON.parse(l));
  assert.equal(rows[1].path, '/p0');
  // Order preserved; both re-scan blocks gone; the isolated burst duplicates kept.
  assert.deepEqual(rows.slice(61).map(r => r.path), ['/p500', '/p501', '/p502', '/p500', '/p501', '/p503']);
  assert.equal(statSync(f.shadow).mode & 0o777, 0o600);

  const dirty = JSON.parse(readFileSync(join(f.summaries, 'shadow-summary-20261020.json'), 'utf8'));
  const expected = structuredClone(f.dirty);
  expected.samples_would_challenge_or_block[0].path = '/a';
  expected.samples_would_challenge_or_block[1].path = '/b';
  assert.equal(readFileSync(join(f.summaries, 'shadow-summary-20261020.json'), 'utf8'), JSON.stringify(expected, null, 2));
  assert.deepEqual(dirty, expected);
  assert.equal(statSync(join(f.summaries, 'shadow-summary-20261020.json')).mode & 0o777, 0o600);
  assert.equal(readFileSync(join(f.summaries, 'shadow-summary-20261019.json'), 'utf8'), JSON.stringify(f.clean, null, 2));
  assert.equal(readFileSync(join(f.summaries, 'other.json'), 'utf8'), JSON.stringify({ path: '/e?x=1' })); // not a summary
  assert.ok(!readdirSync(f.dir).some(n => n.endsWith('.tmp')) && !readdirSync(f.summaries).some(n => n.endsWith('.tmp')));

  old(f.shadow);
  const again = JSON.parse(cleanup('apply', f.shadow, f.summaries, '--dedupe', 'all').stdout); // idempotent
  assert.deepEqual([again.rows_with_query, again.would_drop, again.summary_paths_changed, again.lines_cleaned], [0, 0, 0, 0]);
});

test('shadow-cleanup.mjs --dedupe latest drops only the last run; bad usage exits 2', (t) => {
  const f = cleanupFixture(t);
  old(f.shadow);
  const res = cleanup('apply', f.shadow, f.summaries);
  assert.equal(res.status, 0, res.stderr);
  const rows = readFileSync(f.shadow, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  assert.equal(rows.length, f.lines.length - 55 - 1);
  assert.equal(rows.filter(r => r.ua === CHROME).length, 60); // first re-scan block kept
  assert.equal(rows.at(-1).path, '/p503');
  for (const args of [['nope', f.shadow, f.summaries], ['plan', f.shadow], ['plan', f.shadow, f.summaries, '--dedupe', 'some'], ['plan', f.shadow, f.summaries, '--x']]) {
    assert.equal(cleanup(...args).status, 2, args.join(' '));
  }
});
