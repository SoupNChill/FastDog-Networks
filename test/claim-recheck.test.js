import test from 'node:test';
import assert from 'node:assert/strict';
import { createClaims } from '../src/internal/claims.js';
import { createInternalServer } from '../src/internal/server.js';
import { readJson, writeJson } from '../src/onboard/json.js';
import { issueCredential, validCredential } from '../src/onboard/credentials.js';
import { tempDir } from './helpers/temp-dir.js';
import { fixedClock } from './helpers/clock.js';

function harness(t) {
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
    registry: { closeHost: (host) => closed.push(host) } }, () => changes++);
  return { claims, clock, resolver, records, answers, closed, calls, dataDir, save,
    read: () => readJson('tenant_hostnames.json', [], dataDir), changes: () => changes };
}

test('three tenants: failures suspend only one claim; recovery preserves credentials after expiry', async (t) => {
  const h = harness(t), [a, b, c] = h.records;
  h.answers.set(a.hostname, ['wrong.example.test']);
  const credentialBytes = readJson('agent-credentials.json', [], h.dataDir);
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
  assert.deepEqual(readJson('agent-credentials.json', [], h.dataDir), credentialBytes);
  for (const row of [b, c]) assert.equal(validCredential(row.credential.token, row.hostname, h.dataDir), true);
  assert.deepEqual(readJson('tunnel_hosts.json', [], h.dataDir), [b.hostname, c.hostname]);
  h.answers.delete(a.hostname);
  await h.claims.recheckActiveClaims();
  assert.equal(h.read()[0].status, 'active');
  assert.equal(h.read()[0].recheck_failures, 0);
  assert.equal(validCredential(a.credential.token, a.hostname, h.dataDir), true);
  assert.equal(h.claims.ask(a.hostname), true);
  assert.equal(h.changes(), 2);
  assert.equal(readJson('agent-credentials.json', [], h.dataDir).length, 3);
});

test('success resets consecutive failures; DNS errors and missing A records count once', async (t) => {
  const h = harness(t), [a, b] = h.records;
  h.answers.set(a.hostname, Object.assign(new Error('missing'), { code: 'ENODATA' }));
  h.answers.set(b.hostname, []);
  await h.claims.recheckActiveClaims();
  assert.deepEqual(h.read().map((r) => r.recheck_failures), [1, 1, 0]);
  assert.equal(h.calls.length, 3);
  h.answers.clear();
  await h.claims.recheckActiveClaims();
  assert.deepEqual(h.read().map((r) => r.recheck_failures), [0, 0, 0]);
  h.answers.set(a.hostname, new Error('timeout'));
  await h.claims.recheckActiveClaims({ failuresBeforeDemote: 1 });
  assert.equal(h.read()[0].status, 'suspended');
  await assert.rejects(h.claims.recheckActiveClaims({ failuresBeforeDemote: 0 }), RangeError);
});

test('recovery cannot take another tenant active host; pending claims are not checked', async (t) => {
  const h = harness(t);
  const rows = h.read();
  rows[0].status = 'suspended';
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

test('manual verify restores suspended claim without replacing its credential', async (t) => {
  const h = harness(t), [a] = h.records;
  h.answers.set(a.hostname, []);
  await h.claims.recheckActiveClaims({ failuresBeforeDemote: 1 });
  h.resolver.resolveTxt = async () => [];
  const failed = await h.claims.verify(a.tenant_id, a.hostname);
  assert.equal(failed.status, 'suspended');
  assert.equal(failed.verified, false);
  assert.equal(h.read()[0].credential_id, a.credential_id);
  h.answers.delete(a.hostname);
  h.resolver.resolveTxt = async () => [[a.txt_value]];
  const result = await h.claims.verify(a.tenant_id, a.hostname);
  assert.equal(result.status, 'active');
  assert.equal(result.credential, undefined);
  assert.equal(h.read()[0].credential_id, a.credential_id);
  assert.equal(validCredential(a.credential.token, a.hostname, h.dataDir), true);
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

test('chained proofs use one A lookup; a stalled lookup is bounded and counts as failure', async (t) => {
  const h = harness(t);
  const rows = h.read();
  rows[0].method = 'cname_chain';
  h.save(rows);
  await h.claims.recheckActiveClaims();
  assert.deepEqual(h.calls[0], ['resolve4', rows[0].hostname]);
  assert.equal(h.read()[0].recheck_failures, 0);
  h.resolver.resolveCname = async () => new Promise(() => {});
  await h.claims.recheckActiveClaims({ failuresBeforeDemote: 1 });
  assert.equal(h.read()[2].status, 'suspended');
  assert.deepEqual(h.read().slice(0, 2).map((r) => r.status), ['active', 'active']);
});
