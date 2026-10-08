import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/server.js';
import { createHostStore, isEnforceDenied, validateHostConfig, ENFORCE_DENYLIST } from '../src/config/hosts.js';
import { createAsnDb, loadHostingAsns } from '../src/asn/lookup.js';
import { safeNext } from '../src/edge/routes.js';
import { clientIP, ipPrefix } from '../src/edge/security.js';
import { ipBucketKey } from '../src/middleware/rateLimit.js';
import { redactIp, buildShadowSummary } from '../src/shadow/summary.js';
import { scoreAccessLogLine } from '../src/shadow/score.js';
import { localHeuristic } from '../src/engine/heuristic.js';

async function listen(app) {
  const server = app.listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const { port } = server.address();
  return { server, url: `http://127.0.0.1:${port}` };
}

test('denylist blocks enforce for lease/punchclock/apex', () => {
  for (const h of ENFORCE_DENYLIST) {
    assert.equal(isEnforceDenied(h), true);
    assert.throws(() => validateHostConfig({ mode: 'enforce', enable: true }, { host: h }), e => e.status === 403);
  }
  assert.doesNotThrow(() => validateHostConfig({ mode: 'shadow', enable: true }, { host: 'fastdognetworks.com' }));
  assert.doesNotThrow(() => validateHostConfig({ mode: 'enforce', enable: true }, { host: 'app.customer.example' }));
});

test('demo force requires X-Verdict-Demo header; spoofed Host ignored', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vd-'));
  const app = await createApp({
    keyFile: join(dir, 'keys.json'), usageFile: join(dir, 'usage.json'), decisionFile: join(dir, 'd.jsonl'),
    hostsFile: join(dir, 'hosts.json'),
    clearanceSecret: 'test-secret-32chars-minimum-ok!!',
    demoForce: true, allowBootstrap: true,
  });
  const { server, url } = await listen(app);
  try {
    // Without demo header, force ignored even with spoofed host
    let res = await fetch(`${url}/v1/edge-auth?verdict=block`, {
      headers: {
        'User-Agent': 'Mozilla/5.0',
        'X-Forwarded-Host': 'verdict-demo.fastdognetworks.com',
        Host: 'verdict-demo.fastdognetworks.com',
        'X-Verdict-Force': 'block',
        Accept: 'application/json',
      },
    });
    assert.equal(res.status, 200);
    let body = await res.json();
    assert.notEqual(body.reason, 'demo_force');

    // With Caddy-injected header, force works
    res = await fetch(`${url}/v1/edge-auth?verdict=block`, {
      headers: {
        'User-Agent': 'Mozilla/5.0',
        'X-Forwarded-Host': 'verdict-demo.fastdognetworks.com',
        'X-Verdict-Demo': '1',
        'X-Verdict-Force': 'block',
        Accept: 'application/json',
      },
    });
    assert.equal(res.status, 403);
    body = await res.json();
    assert.equal(body.reason, 'demo_force');
  } finally { server.close(); await app.locals.flush(); }
});

test('hosts API denylist + CRUD', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vd-'));
  const app = await createApp({
    keyFile: join(dir, 'keys.json'), usageFile: join(dir, 'usage.json'), decisionFile: join(dir, 'd.jsonl'),
    hostsFile: join(dir, 'hosts.json'), allowBootstrap: true,
    clearanceSecret: 'test-secret-32chars-minimum-ok!!',
  });
  const { server, url } = await listen(app);
  try {
    const boot = await fetch(`${url}/v1/keys`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const { key } = await boot.json();
    const auth = { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' };
    let res = await fetch(`${url}/v1/hosts/lease.fastdognetworks.com`, {
      method: 'PUT', headers: auth, body: JSON.stringify({ enable: true, mode: 'enforce' }),
    });
    assert.equal(res.status, 403);
    res = await fetch(`${url}/v1/hosts/app.example.com`, {
      method: 'PUT', headers: auth, body: JSON.stringify({ enable: true, mode: 'enforce', fail: 'open' }),
    });
    assert.equal(res.status, 200);
    const row = await res.json();
    assert.equal(row.mode, 'enforce');
    assert.equal(row.fail, 'open');
    res = await fetch(`${url}/v1/hosts`, { headers: auth });
    assert.equal((await res.json()).hosts.length, 1);
  } finally { server.close(); await app.locals.flush(); }
});

test('ASN compact lookup + hosting signal', async () => {
  const db = createAsnDb();
  await db.loadFile(fileURLToPath(new URL('../fixtures/asn-fixture.tsv', import.meta.url)));
  assert.equal(db.lookup('8.8.8.8').asn, 15169);
  assert.equal(db.lookup('1.1.1.1').asn, 13335);
  assert.equal(db.lookup('203.0.113.10').asn, 64500);
  assert.equal(db.lookup('2001:4860:4860::8888').asn, 15169);
  assert.equal(db.lookup('9.9.9.9'), null);
  const hosting = loadHostingAsns();
  assert.equal(hosting.has(15169), true);
  assert.equal(hosting.has(64500), false);
  const d = localHeuristic({
    ip: '8.8.8.8', path: '/', method: 'GET',
    ua: 'Mozilla/5.0', headers: { 'accept-language': 'en' },
    asn: 15169, hosting_asn: true,
  });
  assert.ok(d.reasons.includes('datacenter_asn'));
});

test('safeNext rejects open redirects', () => {
  assert.equal(safeNext('https://evil.com'), '/');
  assert.equal(safeNext('//evil.com'), '/');
  assert.equal(safeNext('/\\evil'), '/');
  assert.equal(safeNext('/ok/path'), '/ok/path');
  assert.equal(safeNext('/javascript:alert(1)'), '/');
});

test('clientIP ignores spoofed XFF from non-loopback peer', () => {
  const req = {
    get(h) {
      const m = { 'x-forwarded-for': '1.2.3.4', 'x-real-ip': '1.2.3.4' };
      return m[h.toLowerCase()];
    },
    socket: { remoteAddress: '9.9.9.9' },
  };
  assert.equal(clientIP(req), '9.9.9.9');
  const loop = {
    get(h) {
      const m = { 'x-forwarded-for': '8.8.8.8, 10.0.0.1' };
      return m[h.toLowerCase()];
    },
    socket: { remoteAddress: '127.0.0.1' },
  };
  assert.equal(clientIP(loop), '10.0.0.1');
});

test('IPv6 rate-limit bucket is /64', () => {
  assert.equal(ipBucketKey('2001:db8:abcd:0012:0:0:0:1'), ipPrefix('2001:db8:abcd:0012:0:0:0:1'));
  assert.equal(ipBucketKey('2001:db8:abcd:0012::9'), ipBucketKey('2001:db8:abcd:0012::1'));
});

test('shadow summary redacts IPs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vd-sh-'));
  const file = join(dir, 'shadow.jsonl');
  const day = new Date().toISOString().slice(0, 10);
  await writeFile(file, JSON.stringify({
    ts: day + 'T12:00:00.000Z', host: 'fastdognetworks.com', ip: '203.0.113.9',
    path: '/login', method: 'GET', action: 'challenge', reason: 'ambiguous_automation',
    reasons: ['headless'], score: 0.5, ua: 'HeadlessChrome',
  }) + '\n');
  const summary = await buildShadowSummary(file, { day });
  assert.equal(summary.counts.challenge, 1);
  assert.equal(summary.samples_would_challenge_or_block[0].ip_redacted, '203.0.113.0/24');
  assert.ok(!JSON.stringify(summary).includes('203.0.113.9'));
});

test('shadow scorer only accepts apex/www/demo hosts', () => {
  const hosting = loadHostingAsns();
  assert.equal(scoreAccessLogLine(JSON.stringify({
    host: 'lease.fastdognetworks.com', request: { method: 'GET', uri: '/', headers: { 'User-Agent': 'x' } },
  }), { hosting }), null);
  assert.ok(scoreAccessLogLine(JSON.stringify({
    ts: new Date().toISOString(), host: 'www.fastdognetworks.com',
    client_ip: '203.0.113.1',
    request: { method: 'GET', uri: '/', headers: { 'User-Agent': 'Mozilla/5.0', 'Accept-Language': 'en' } },
  }), { hosting }));
});

test('ASN binary round-trip keeps lookups', async () => {
  const { createCompiler, serialize, deserialize, createAsnDb } = await import('../src/asn/lookup.js');
  const { readFile } = await import('node:fs/promises');
  const c = createCompiler();
  for (const line of (await readFile(fileURLToPath(new URL('../fixtures/asn-fixture.tsv', import.meta.url)), 'utf8')).split('\n')) c.line(line);
  const bin = serialize(c.finish());
  const dir = await mkdtemp(join(tmpdir(), 'vd-asn-'));
  await writeFile(join(dir, 'asn.bin'), bin);
  const db = createAsnDb();
  await db.loadFile(join(dir, 'asn.bin'));
  assert.equal(db.lookup('1.1.1.1').asn, 13335);
  assert.equal(db.lookup('2001:4860:4860::1').asn, 15169);
  assert.throws(() => deserialize(Buffer.from('garbage-garbage-garbage')));
});

test('read-only key can GET ops/hosts but cannot write or decide', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vd-ro-'));
  const { createKeyStore } = await import('../src/auth/keys.js');
  const ks = createKeyStore(join(dir, 'keys.json'));
  await ks.load();
  const full = await ks.create('admin');
  const ro = await ks.create('panel', { scope: 'read' });
  assert.equal(ro.scope, 'read');
  const app = await createApp({ keyFile: join(dir, 'keys.json'), usageFile: join(dir, 'u.json'), decisionFile: join(dir, 'd.jsonl'), hostsFile: join(dir, 'h.json'), clearanceSecret: 'test-secret-32chars-minimum-ok!!' });
  const { server, url } = await listen(app);
  try {
    const h = k => ({ Authorization: `Bearer ${k}`, 'Content-Type': 'application/json' });
    assert.equal((await fetch(`${url}/v1/ops/metrics`, { headers: h(ro.key) })).status, 200);
    assert.equal((await fetch(`${url}/v1/hosts`, { headers: h(ro.key) })).status, 200);
    assert.equal((await fetch(`${url}/v1/hosts/a.example.com`, { method: 'PUT', headers: h(ro.key), body: '{"mode":"shadow"}' })).status, 403);
    assert.equal((await fetch(`${url}/v1/decide`, { method: 'POST', headers: h(ro.key), body: '{}' })).status, 403);
    assert.equal((await fetch(`${url}/v1/hosts/a.example.com`, { method: 'PUT', headers: h(full.key), body: '{"mode":"shadow"}' })).status, 200);
  } finally { server.close(); await app.locals.flush(); }
});

test('shadow rows store ISO ts and IP prefix only (no raw IP)', () => {
  const row = scoreAccessLogLine(JSON.stringify({ ts: 1791487580.11, host: 'fastdognetworks.com', client_ip: '198.51.100.77', request: { method: 'GET', uri: '/', headers: { 'User-Agent': ['Mozilla/5.0'] } } }), { hosting: loadHostingAsns() });
  assert.match(row.ts, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(row.ip_prefix, '198.51.100.0/24');
  assert.ok(!JSON.stringify(row).includes('198.51.100.77'));
});

test('hosting list excludes consumer privacy relays (Cloudflare WARP)', () => {
  assert.equal(loadHostingAsns().has(13335), false);
});
