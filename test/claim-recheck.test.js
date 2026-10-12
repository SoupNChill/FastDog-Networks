import test from 'node:test';
import assert from 'node:assert/strict';
import { createClaims } from '../src/internal/claims.js';
import { createInternalServer } from '../src/internal/server.js';
import { readJson, writeJson } from '../src/onboard/json.js';
import { issueCredential, validCredential } from '../src/onboard/credentials.js';
import { tempDir } from './helpers/temp-dir.js';
import { fixedClock } from './helpers/clock.js';

function harness(t, options = {}) {
  const dataDir = tempDir(t);
  const clock = fixedClock();
  const closed = [], calls = [], answers = new Map();
  let changes = 0;
  const records = ['a', 'b', 'c'].map((letter, i) => {
    const hostname = `${letter}.example.test`, tenant_id = `t_${letter.repeat(20)}`;
    const credential = issueCredential({ hostname, tenant_id }, dataDir, clock.now);
    return { hostname, tenant_id, status: 'active', method: i === 1 ? 'a_record' : 'cname',
      credential_id: credential.id, txt_value: `synthetic-${letter}`, created_at: new Date(clock.now()).toISOString(),
      expires_at: new Date(clock.now() - 1).toISOString(), credential };
  });
  const save = (rows) => writeJson('tenant_hostnames.json', rows, 0o600, dataDir);
  save(records.map(({ credential, ...row }) => row));
  writeJson('tunnel_hosts.json', records.map((r) => r.hostname), 0o600, dataDir);
  const resolver = Object.fromEntries(['resolveCname', 'resolve4'].map((type) => [type, async (host) => {
    calls.push([type, host]);
    const value = answers.get(host);
    if (value instanceof Error) throw value;
    return value ?? (type === 'resolve4' ? ['192.0.2.1'] : ['attach.example.test']);
  }]));
  const claims = createClaims({ dataDir, now: clock.now, resolver, attachTarget: 'attach.example.test',
    altAttachTarget: 'edge.example.test', edgePublicIp: '192.0.2.1', reservedSuffixes: [],
    registry: { closeHost: (host) => closed.push(host) }, ...options }, () => changes++);
  return { claims, clock, resolver, records, answers, closed, calls, dataDir, save,
    read: () => readJson('tenant_hostnames.json', [], dataDir), changes: () => changes };
}

test('three tenants: suspension revokes credentials and routing alone cannot restore', async (t) => {
  const h = harness(t), [a, b, c] = h.records;
  h.answers.set(a.hostname, ['wrong.example.test']);
  for (let run = 1; run <= 3; run++) {
    h.calls.length = 0;
    await h.claims.recheckActiveClaims({ now: h.clock.now(), resolver: h.resolver });
    assert.equal(h.calls.length, 3);
    assert.equal(new Set(h.calls.map(([, host]) => host)).size, 3);
    const rows = h.read();
    assert.equal(rows[0].recheck_failures, run);
    assert.equal(rows[0].last_rechecked_at, new Date(h.clock.now()).toISOString());
    assert.equal(rows[0].status, run === 3 ? 'suspended' : 'active');
    for (const row of rows.slice(1)) { assert.equal(row.status, 'active'); assert.equal(row.recheck_failures, 0); }
    h.clock.advance(21600000);
  }
  assert.deepEqual(h.closed, [a.hostname]);
  assert.equal(h.changes(), 1);
  assert.equal(h.claims.ask(a.hostname), false);
  assert.equal(h.claims.get(a.tenant_id, a.hostname).status, 'suspended');
  assert.equal(h.claims.get(a.tenant_id, a.hostname).dns, undefined);
  assert.equal(h.claims.list(a.tenant_id).hostnames.length, 1);
  assert.equal(validCredential(a.credential.token, a.hostname, h.dataDir), false);
  assert.ok(readJson('agent-credentials.json', [], h.dataDir)[0].revoked_at);
  for (const row of [b, c]) assert.equal(validCredential(row.credential.token, row.hostname, h.dataDir), true);
  assert.deepEqual(readJson('tunnel_hosts.json', [], h.dataDir), [b.hostname, c.hostname]);
  h.answers.delete(a.hostname);
  await h.claims.recheckActiveClaims();
  assert.equal(h.read()[0].status, 'suspended');
  assert.equal(h.read()[0].recheck_failures, 3);
  assert.equal(validCredential(a.credential.token, a.hostname, h.dataDir), false);
  assert.equal(h.claims.ask(a.hostname), false);
  assert.equal(h.changes(), 1);
  assert.equal(readJson('agent-credentials.json', [], h.dataDir).length, 3);
});

test('success resets consecutive failures; authoritative absence and missing A records count once', async (t) => {
  const h = harness(t), [a, b] = h.records;
  h.answers.set(a.hostname, Object.assign(new Error('missing'), { code: 'ENODATA' }));
  h.answers.set(b.hostname, []);
  await h.claims.recheckActiveClaims();
  assert.deepEqual(h.read().map((r) => r.recheck_failures), [1, 1, 0]);
  assert.equal(h.calls.length, 3);
  h.answers.clear();
  await h.claims.recheckActiveClaims();
  assert.deepEqual(h.read().map((r) => r.recheck_failures), [0, 0, 0]);
  h.answers.set(a.hostname, Object.assign(new Error('missing'), { code: 'ENOTFOUND' }));
  await h.claims.recheckActiveClaims({ failuresBeforeDemote: 1 });
  assert.equal(h.read()[0].status, 'suspended');
  await assert.rejects(h.claims.recheckActiveClaims({ failuresBeforeDemote: 0 }), RangeError);
});

test('recovery cannot take another tenant active host; pending claims are not checked', async (t) => {
  const h = harness(t);
  const rows = h.read();
  rows[0].status = 'suspended';
  rows[0].expires_at = new Date(h.clock.now() + 86400000).toISOString();
  rows[1].hostname = rows[0].hostname;
  rows[2].status = 'pending';
  rows[2].expires_at = new Date(h.clock.now() + 86400000).toISOString();
  h.save(rows);
  await h.claims.recheckActiveClaims();
  assert.equal(h.read()[0].status, 'suspended');
  assert.equal(h.read()[1].status, 'active');
  assert.deepEqual(h.read()[2], rows[2]);
  assert.deepEqual(h.closed, []);
  assert.equal(h.changes(), 0);
});

test('in-flight checks cannot resurrect deleted claims; overlapping runs do no extra DNS', async (t) => {
  const h = harness(t);
  let release;
  let lookups = 0;
  const pending = new Promise((resolve) => { release = resolve; });
  const run = h.claims.recheckActiveClaims({ resolver: {
    resolveCname: async () => { lookups++; await pending; return []; },
    resolve4: async () => { lookups++; return []; },
  } });
  await Promise.resolve();
  await h.claims.recheckActiveClaims();
  assert.equal(h.calls.length, 0);
  h.claims.delete(h.records[0].tenant_id, h.records[0].hostname);
  release();
  await run;
  assert.equal(lookups, 3);
  assert.equal(h.read().length, 2);
});

test('manual restore requires both proofs and issues a new credential', async (t) => {
  const h = harness(t), [a] = h.records;
  h.answers.set(a.hostname, []);
  await h.claims.recheckActiveClaims({ failuresBeforeDemote: 1 });
  h.answers.delete(a.hostname);
  h.resolver.resolveTxt = async () => [['wrong-proof']];
  const failed = await h.claims.verify(a.tenant_id, a.hostname);
  assert.equal(failed.status, 'suspended');
  assert.equal(failed.verified, false);
  assert.equal(h.read()[0].credential_id, a.credential_id);
  h.answers.delete(a.hostname);
  h.resolver.resolveTxt = async () => [[a.txt_value]];
  const result = await h.claims.verify(a.tenant_id, a.hostname);
  assert.equal(result.status, 'active');
  assert.notEqual(result.credential.id, a.credential_id);
  assert.equal(h.read()[0].credential_id, result.credential.id);
  assert.equal(validCredential(a.credential.token, a.hostname, h.dataDir), false);
  assert.equal(validCredential(result.credential.token, a.hostname, h.dataDir), true);
});

test('scheduler defaults off, runs every six hours when enabled, and clears on close', (t) => {
  const scheduled = [], cleared = [];
  t.mock.method(globalThis, 'setInterval', (fn, ms) => {
    const timer = { unref() {} }; scheduled.push({ fn, ms, timer }); return timer;
  });
  t.mock.method(globalThis, 'clearInterval', (timer) => cleared.push(timer));
  const opts = { portalKey: 'synthetic-test-key-'.repeat(3), dataDir: tempDir(t) };
  const off = createInternalServer(opts);
  off.emit('listening');
  assert.equal(scheduled.length, 0);
  const on = createInternalServer({ ...opts, recheckEnabled: true });
  on.emit('listening');
  assert.equal(scheduled.length, 1);
  assert.equal(scheduled[0].ms, 21600000);
  on.emit('close');
  assert.deepEqual(cleared, [scheduled[0].timer]);
});

test('chained proofs use one A lookup; a stalled lookup is bounded and skipped', async (t) => {
  const h = harness(t);
  const rows = h.read();
  rows[0].method = 'cname_chain';
  h.save(rows);
  await h.claims.recheckActiveClaims();
  assert.deepEqual(h.calls[0], ['resolve4', rows[0].hostname]);
  assert.equal(h.read()[0].recheck_failures, 0);
  h.resolver.resolveCname = async () => new Promise(() => {});
  await h.claims.recheckActiveClaims({ failuresBeforeDemote: 1 });
  assert.equal(h.read()[2].status, 'active');
  assert.equal(h.read()[2].recheck_failures, 0);
  assert.deepEqual(h.read().slice(0, 2).map((r) => r.status), ['active', 'active']);
});

test('resolver outages preserve counters and timestamps across repeated runs', async (t) => {
  const h = harness(t);
  h.answers.set(h.records[0].hostname, []);
  await h.claims.recheckActiveClaims();
  const before = h.read();
  for (const code of ['SERVFAIL', 'ESERVFAIL', 'ETIMEOUT', 'dns_timeout', 'ECONNREFUSED']) {
    for (const row of h.records) h.answers.set(row.hostname, Object.assign(new Error(code), { code }));
    h.clock.advance(21600000);
    await h.claims.recheckActiveClaims();
    assert.deepEqual(h.read(), before);
  }
  assert.equal(h.changes(), 0);
  assert.deepEqual(h.closed, []);
});

test('suspended claims expire after 24 hours and cannot verify even with valid proofs', async (t) => {
  const h = harness(t), [a] = h.records;
  h.answers.set(a.hostname, []);
  await h.claims.recheckActiveClaims({ failuresBeforeDemote: 1 });
  assert.equal(Date.parse(h.read()[0].expires_at), h.clock.now() + 86400000);
  h.clock.advance(86400000 - 1);
  assert.equal(h.claims.get(a.tenant_id, a.hostname).status, 'suspended');
  h.clock.advance(1);
  h.answers.clear();
  h.resolver.resolveTxt = async () => [[a.txt_value]];
  assert.deepEqual(h.claims.list(a.tenant_id).hostnames, []);
  await assert.rejects(h.claims.verify(a.tenant_id, a.hostname), { code: 'hostname_not_found' });
  assert.equal(validCredential(a.credential.token, a.hostname, h.dataDir), false);
  const fresh = h.claims.create(a.tenant_id, { hostname: a.hostname, hostname_limit: 1 });
  assert.equal(fresh.status, 201);
  assert.notEqual(fresh.body.dns.txt.value, a.txt_value);
});

test('first to prove wins among suspended and pending claims regardless of file order', async (t) => {
  for (const winner of [1, 2]) {
    const h = harness(t), [a] = h.records;
    const rows = h.read().map((row, i) => ({ ...row, hostname: a.hostname,
      status: i === 2 ? 'pending' : 'suspended', expires_at: new Date(h.clock.now() + 86400000).toISOString() }));
    h.save(rows);
    await h.claims.recheckActiveClaims();
    assert.equal(h.calls.length, 0);
    assert.deepEqual(h.read(), rows);
    h.resolver.resolveTxt = async () => [[rows[winner].txt_value]];
    const result = await h.claims.verify(rows[winner].tenant_id, a.hostname);
    assert.equal(result.verified, true);
    assert.ok(result.credential);
    await assert.rejects(h.claims.verify(a.tenant_id, a.hostname), { code: 'hostname_unavailable' });
    assert.equal(h.read().filter((row) => row.status === 'active').length, 1);
    assert.equal(h.read()[winner].status, 'active');
  }
});


test('three tenants: default inconclusive cap suspends only the stale owner and restore resets streak', async (t) => {
  const h = harness(t), [a, b, c] = h.records;
  for (let run = 1; run <= 10; run++) {
    h.answers.set(a.hostname, Object.assign(new Error('resolver failure'), { code: run % 2 ? 'ETIMEOUT' : 'SERVFAIL' }));
    h.clock.advance(21600000);
    await h.claims.recheckActiveClaims();
    const [row, ...others] = h.read();
    assert.equal(row.recheck_inconclusive, run);
    assert.equal(row.recheck_failures ?? 0, Math.max(0, run - 7));
    assert.equal(row.status, run === 10 ? 'suspended' : 'active');
    assert.equal(row.last_rechecked_at, new Date(h.clock.now()).toISOString());
    for (const other of others) {
      assert.equal(other.status, 'active');
      assert.equal(other.recheck_inconclusive, 0);
      assert.equal(other.recheck_failures, 0);
    }
  }
  assert.deepEqual(h.closed, [a.hostname]);
  assert.equal(h.changes(), 1);
  assert.equal(h.claims.ask(a.hostname), false);
  assert.equal(validCredential(a.credential.token, a.hostname, h.dataDir), false);
  for (const row of [b, c]) assert.equal(validCredential(row.credential.token, row.hostname, h.dataDir), true);
  assert.deepEqual(readJson('tunnel_hosts.json', [], h.dataDir), [b.hostname, c.hostname]);
  h.answers.clear();
  h.resolver.resolveTxt = async () => [[a.txt_value]];
  await h.claims.verify(a.tenant_id, a.hostname);
  assert.equal(h.read()[0].recheck_inconclusive, 0);
  assert.equal(h.read()[0].recheck_failures, 0);
});

test('configured cap and conclusive results reset the inconclusive streak', async (t) => {
  const h = harness(t, { inconclusiveBeforeFailure: 2 }), [a] = h.records;
  const error = Object.assign(new Error('timeout'), { code: 'ETIMEOUT' });
  h.answers.set(a.hostname, error);
  await h.claims.recheckActiveClaims();
  await h.claims.recheckActiveClaims();
  assert.equal(h.read()[0].recheck_failures, 1);
  h.answers.set(a.hostname, []);
  await h.claims.recheckActiveClaims();
  assert.equal(h.read()[0].recheck_inconclusive, 0);
  assert.equal(h.read()[0].recheck_failures, 2);
  h.answers.set(a.hostname, error);
  await h.claims.recheckActiveClaims();
  assert.equal(h.read()[0].recheck_inconclusive, 1);
  assert.equal(h.read()[0].recheck_failures, 2);
  h.answers.clear();
  await h.claims.recheckActiveClaims();
  assert.equal(h.read()[0].recheck_inconclusive, 0);
  assert.equal(h.read()[0].recheck_failures, 0);
  h.answers.set(a.hostname, error);
  await h.claims.recheckActiveClaims({ inconclusiveBeforeFailure: 1 });
  assert.equal(h.read()[0].recheck_failures, 1);
  for (const value of [0, -1, 1.5, '2', null, NaN, Infinity]) {
    await assert.rejects(h.claims.recheckActiveClaims({ inconclusiveBeforeFailure: value }), RangeError);
  }
});

test('majority outage freezes existing streaks but still applies conclusive results', async (t) => {
  const h = harness(t, { inconclusiveBeforeFailure: 2 }), [a, b, c] = h.records;
  const error = Object.assign(new Error('resolver failure'), { code: 'SERVFAIL' });
  h.answers.set(a.hostname, error);
  await h.claims.recheckActiveClaims();
  const before = h.read()[0];
  h.answers.set(b.hostname, error);
  h.answers.set(c.hostname, []);
  h.clock.advance(21600000);
  await h.claims.recheckActiveClaims();
  assert.deepEqual(h.read()[0], before);
  assert.equal(h.read()[1].recheck_inconclusive, 0);
  assert.equal(h.read()[2].recheck_failures, 1);
  h.answers.delete(b.hostname);
  await h.claims.recheckActiveClaims();
  assert.equal(h.read()[0].recheck_inconclusive, 2);
  assert.equal(h.read()[0].recheck_failures, 1);
});

test('exactly half inconclusive advances counters; pending claims do not dilute outage ratio', async (t) => {
  const h = harness(t), [a, b] = h.records;
  const rows = h.read();
  rows[2].status = 'pending';
  rows[2].expires_at = new Date(h.clock.now() + 86400000).toISOString();
  h.save(rows);
  const error = Object.assign(new Error('timeout'), { code: 'ETIMEOUT' });
  h.answers.set(a.hostname, error);
  await h.claims.recheckActiveClaims({ inconclusiveBeforeFailure: 1 });
  assert.equal(h.read()[0].recheck_inconclusive, 1);
  assert.equal(h.read()[0].recheck_failures, 1);
  h.answers.set(b.hostname, error);
  const before = h.read();
  await h.claims.recheckActiveClaims({ inconclusiveBeforeFailure: 1 });
  assert.deepEqual(h.read(), before);
});
