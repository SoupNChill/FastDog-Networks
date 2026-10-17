import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import net from 'node:net';
import { tempDir } from './helpers/temp-dir.js';
import { internalHarness, hostPath } from './helpers/internal.js';
import { trafficStats, shadowStats, certInfo, testSite, liveState, safeHost } from '../src/internal/site-status.js';
import { createSiteStatus } from '../src/internal/site-status-service.js';

const tid = 't_aaaaaaaaaaaaaaaaaaaa';
const other = 't_bbbbbbbbbbbbbbbbbbbb';
const NOW = Date.parse('2026-01-02T12:00:00Z');
const SINCE = NOW - 3 * 86400000; // claim older than the 24h window: no claim-time filtering
const line = (ageMs, extra = {}) => JSON.stringify({ ts: (NOW - ageMs) / 1000, request: { method: 'GET', uri: '/' }, duration: 0.01, status: 200, ...extra });

test('traffic stats bucket 24h of the per-host access log and compute p50 and 5xx', async (t) => {
  const dir = tempDir(t);
  writeFileSync(join(dir, 'app.example.test.log'), [
    line(10 * 60000, { duration: 0.002 }), line(20 * 60000, { duration: 0.004, status: 502 }), line(90 * 60000, { duration: 0.1 }),
    line(25 * 3600000), 'not json', line(-60000), '',
  ].join('\n'));
  const stats = await trafficStats('app.example.test', { logDir: dir, since: SINCE, now: () => NOW });
  assert.equal(stats.available, true);
  assert.equal(stats.total, 3);
  assert.equal(stats.hourly.length, 24);
  assert.equal(stats.hourly[23], 2);
  assert.equal(stats.hourly[22], 1);
  assert.equal(stats.p50_ms, 4);
  assert.equal(stats.errors_5xx, 1);
  assert.deepEqual(await trafficStats('missing.example.test', { logDir: dir, since: SINCE, now: () => NOW }), { available: false });
  await assert.rejects(trafficStats('../etc/passwd', { logDir: dir }));
  assert.throws(() => safeHost('a/b.example.test'));
  assert.throws(() => safeHost('..'));
});

test('shadow stats count only this host within 24h and stay labelled shadow', async (t) => {
  const file = join(tempDir(t), 'shadow.jsonl');
  const at = (ms) => new Date(NOW - ms).toISOString();
  writeFileSync(file, [
    { ts: at(1000), host: 'app.example.test', action: 'block' }, { ts: at(2000), host: 'app.example.test', action: 'challenge' },
    { ts: at(3000), host: 'app.example.test', action: 'allow' }, { ts: at(4000), host: 'xapp.example.test', action: 'block' },
    { ts: at(30 * 3600000), host: 'app.example.test', action: 'block' },
  ].map((v) => JSON.stringify(v)).join('\n'));
  assert.deepEqual(await shadowStats('app.example.test', { shadowFile: file, since: SINCE, now: () => NOW }),
    { available: true, shadow: true, scored: 3, would_block: 1, would_challenge: 1 });
  assert.deepEqual(await shadowStats('app.example.test', { shadowFile: join(file, 'nope'), since: SINCE, now: () => NOW }), { available: false, shadow: true });
});

test('live state needs a connected agent, a non-failing origin and a valid unexpired cert', () => {
  const cert = { valid: true, expires_at: new Date(NOW + 86400000).toISOString() };
  assert.deepEqual(liveState({ agent: { connected: true, origin_reachable: true }, cert, since: SINCE, now: () => NOW }), { live: true, reasons: [] });
  assert.equal(liveState({ agent: { connected: true, origin_reachable: null }, cert, since: SINCE, now: () => NOW }).live, true, 'older agents degrade to unknown, not down');
  assert.deepEqual(liveState({ agent: { connected: true, origin_reachable: false }, cert, since: SINCE, now: () => NOW }).reasons, ['origin_unreachable']);
  assert.deepEqual(liveState({ agent: { connected: false }, cert: null, since: SINCE, now: () => NOW }).reasons, ['agent_disconnected', 'certificate_missing']);
  assert.deepEqual(liveState({ agent: { connected: true }, cert: { ...cert, expires_at: new Date(NOW - 1).toISOString() }, since: SINCE, now: () => NOW }).reasons, ['certificate_expired']);
});

test('probes fail closed on an unreachable local listener', async () => {
  const server = net.createServer((socket) => socket.destroy());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    assert.equal(await certInfo('app.example.test', { tlsPort: port, timeout: 1000 }), null);
    const result = await testSite('app.example.test', { tlsPort: port, timeout: 1000 });
    assert.equal(result.ok, false);
    assert.equal(result.status, null);
    assert.equal(result.error, 'unreachable');
  } finally { server.close(); }
});

test('status service only probes the loopback listener', () => {
  for (const addr of ['10.0.0.1:443', 'example.test:443', '127.0.0.1:0', '0.0.0.0:443']) {
    assert.throws(() => createSiteStatus({ statusTlsAddr: addr, agent: () => ({}) }), /loopback/);
  }
  assert.doesNotThrow(() => createSiteStatus({ statusTlsAddr: '127.0.0.1:8443', agent: () => ({}) }));
});

test('internal status and test routes are tenant-scoped, active-only, cached and rate limited', async (t) => {
  const probed = [];
  const siteProbes = {
    trafficStats: async (host) => { probed.push(['traffic', host]); return { available: true, total: 5, hourly: new Array(24).fill(0), p50_ms: 3, errors_5xx: 0 }; },
    shadowStats: async (host) => { probed.push(['shadow', host]); return { available: true, shadow: true, scored: 2, would_block: 1, would_challenge: 0 }; },
    certInfo: async (host, opts) => { probed.push(['cert', host, opts.tlsHost]); return { valid: true, expires_at: '2099-01-01T00:00:00.000Z', issuer: 'Test CA' }; },
    testSite: async (host, opts) => { probed.push(['test', host, opts.tlsHost]); return { ok: true, status: 200, ms: 12, cert: null }; },
  };
  const h = await internalHarness(t, { siteProbes, statusTlsAddr: '127.0.0.1:443' });
  await h.activate(tid, 'app.example.test');
  await h.create(tid, 'pending.example.test');
  h.agents.set('app.example.test', { connected: true, originReachable: true, agentVersion: '0.1.2' });
  const status = await h.request(hostPath(tid, 'app.example.test', '/status'));
  assert.equal(status.status, 200);
  assert.equal(status.body.live, true);
  assert.equal(status.body.agent.agent_version, '0.1.2');
  assert.equal(status.body.verdict.shadow, true);
  assert.equal(status.body.traffic.total, 5);
  await h.request(hostPath(tid, 'app.example.test', '/status'));
  assert.equal(probed.filter(([kind]) => kind === 'cert').length, 1, 'second status read is cached');
  assert.equal((await h.request(hostPath(other, 'app.example.test', '/status'))).status, 404);
  assert.equal((await h.request(hostPath(other, 'app.example.test', '/test'), { method: 'POST' })).status, 404);
  assert.equal((await h.request(hostPath(tid, 'pending.example.test', '/status'))).status, 409);
  assert.equal((await h.request(hostPath(tid, 'app.example.test', '/status'), { method: 'POST' })).status, 405);
  assert.equal((await h.request(hostPath(tid, 'app.example.test', '/test'))).status, 405);
  assert.equal((await h.request(hostPath(tid, 'app.example.test', '/status'), { headers: { 'x-fastdog-portal-key': 'wrong' } })).status, 401);
  for (let i = 0; i < 10; i++) {
    const run = await h.request(hostPath(tid, 'app.example.test', '/test'), { method: 'POST' });
    assert.equal(run.status, 200);
    assert.deepEqual(Object.keys(run.body).sort(), ['cert', 'error', 'hostname', 'ms', 'ok', 'status', 'tested_at']);
  }
  const limited = await h.request(hostPath(tid, 'app.example.test', '/test'), { method: 'POST' });
  assert.equal(limited.status, 429);
  assert.ok(probed.every(([, host, addr]) => host === 'app.example.test' && (addr === undefined || addr === '127.0.0.1')));
});

test('customer shadow counts: only this host, only the last 24 hours, file contents never leak', async (t) => {
  const dir = tempDir(t);
  const counts = join(dir, 'customer-counts.json');
  const hour = Math.floor(NOW / 3600000);
  writeFileSync(counts, JSON.stringify({ v: 1, hosts: {
    'app.example.test': { [hour]: { scored: 5, block: 1, challenge: 2 }, [hour - 23]: { scored: 1, block: 0, challenge: 1 }, [hour - 30]: { scored: 9, block: 9, challenge: 0 } },
    'other.example.test': { [hour]: { scored: 50, block: 50, challenge: 0 } },
  } }));
  assert.deepEqual(await shadowStats('app.example.test', { countsFile: counts, shadowFile: join(dir, 'none'), since: SINCE, now: () => NOW }),
    { available: true, shadow: true, scored: 6, would_block: 1, would_challenge: 3 });
  // A host with no counts falls back to the first-party row log (here missing).
  assert.deepEqual(await shadowStats('new.example.test', { countsFile: counts, shadowFile: join(dir, 'none'), since: SINCE, now: () => NOW }), { available: false, shadow: true });
  // Inherited names and malformed buckets are ignored.
  writeFileSync(counts, JSON.stringify({ v: 1, hosts: { 'app.example.test': { [hour]: { scored: -4, block: 'x', challenge: 1 } } } }));
  assert.deepEqual(await shadowStats('app.example.test', { countsFile: counts, since: SINCE, now: () => NOW }),
    { available: true, shadow: true, scored: 0, would_block: 0, would_challenge: 1 });
  assert.deepEqual(await shadowStats('constructor.example.test', { countsFile: counts, since: SINCE, now: () => NOW }), { available: false, shadow: true });
});

test('a re-claimed hostname never shows the previous owner\'s traffic or shadow counts', async (t) => {
  const dir = tempDir(t);
  const since = new Date(NOW - 90 * 60000).toISOString(); // 10:30Z
  const opts = { since, now: () => NOW };
  // Traffic: lines before the claim belong to the previous owner.
  writeFileSync(join(dir, 'app.example.test.log'), [
    line(5 * 3600000, { status: 502 }), line(100 * 60000), line(91 * 60000), line(60 * 60000), line(10 * 60000),
  ].join('\n'));
  const traffic = await trafficStats('app.example.test', { logDir: dir, ...opts });
  assert.equal(traffic.total, 2);
  assert.equal(traffic.errors_5xx, 0);
  // First-party shadow rows.
  const rows = join(dir, 'shadow.jsonl');
  const at = (ms) => new Date(NOW - ms).toISOString();
  writeFileSync(rows, [
    { ts: at(5 * 3600000), host: 'app.example.test', action: 'block' }, { ts: at(95 * 60000), host: 'app.example.test', action: 'block' },
    { ts: at(30 * 60000), host: 'app.example.test', action: 'challenge' },
  ].map((v) => JSON.stringify(v)).join('\n'));
  assert.deepEqual(await shadowStats('app.example.test', { shadowFile: rows, ...opts }),
    { available: true, shadow: true, scored: 1, would_block: 0, would_challenge: 1 });
  // Hourly counts: the bucket containing the claim (10:00Z) could hold old data, so it is excluded.
  const counts = join(dir, 'customer-counts.json');
  const hour = Math.floor(NOW / 3600000); // 12:00Z
  writeFileSync(counts, JSON.stringify({ v: 1, hosts: { 'app.example.test': {
    [hour - 5]: { scored: 100, block: 100, challenge: 0 }, [hour - 2]: { scored: 40, block: 40, challenge: 0 },
    [hour - 1]: { scored: 3, block: 1, challenge: 1 }, [hour]: { scored: 2, block: 0, challenge: 1 } } } }));
  assert.deepEqual(await shadowStats('app.example.test', { countsFile: counts, ...opts }),
    { available: true, shadow: true, scored: 5, would_block: 1, would_challenge: 2 });
  // A claim on an exact hour boundary includes that bucket.
  assert.equal((await shadowStats('app.example.test', { countsFile: counts, since: (hour - 1) * 3600000, now: () => NOW })).scored, 5);
  // Missing or unparseable claim time fails closed.
  for (const bad of [undefined, null, '', 'not a date', '1', 'Oct 16 2026', NaN]) {
    assert.deepEqual(await shadowStats('app.example.test', { countsFile: counts, shadowFile: rows, since: bad, now: () => NOW }), { available: false, shadow: true });
    assert.deepEqual(await trafficStats('app.example.test', { logDir: dir, since: bad, now: () => NOW }), { available: false });
  }
});

test('status service passes the current claim time to the probes and fails closed without it', async (t) => {
  const seen = [];
  const siteProbes = {
    trafficStats: async (host, o) => { seen.push(o.since); return { available: false }; },
    shadowStats: async (host, o) => { seen.push(o.since); return { available: false, shadow: true }; },
    certInfo: async () => null,
  };
  const h = await internalHarness(t, { siteProbes, statusTlsAddr: '127.0.0.1:443' });
  await h.activate(tid, 'app.example.test');
  await h.request(hostPath(tid, 'app.example.test', '/status'));
  assert.equal(seen.length, 2);
  assert.ok(seen.every((v) => Number.isFinite(Date.parse(v))), 'verified_at is threaded through');
  const svc = createSiteStatus({ agent: () => ({}), claimSince: () => null, siteProbes: { certInfo: async () => null },
    accessLogDir: tempDir(t), countsFile: join(tempDir(t), 'none.json') });
  const out = await svc.status(tid, 'app.example.test');
  assert.deepEqual(out.traffic, { available: false });
  assert.deepEqual(out.verdict, { available: false, shadow: true });
});

test('an active claim record without verified_at reports traffic and verdict as not available', async (t) => {
  const h = await internalHarness(t, { statusTlsAddr: '127.0.0.1:443', siteProbes: { certInfo: async () => null } });
  await h.activate(tid, 'app.example.test');
  const file = join(h.dataDir, 'tenant_hostnames.json');
  const records = JSON.parse(readFileSync(file, 'utf8'));
  for (const record of records) delete record.verified_at;
  writeFileSync(file, JSON.stringify(records));
  const res = await h.request(hostPath(tid, 'app.example.test', '/status'));
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.traffic, { available: false });
  assert.deepEqual(res.body.verdict, { available: false, shadow: true });
});
