import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createClaims } from '../src/internal/claims.js';
import { createTlsAsk } from '../src/internal/tls-ask.js';
import { editTestTenants, isTestLabelHost, testTenants } from '../src/internal/test-labels.js';
import { ENFORCE_DENYLIST } from '../verdict/src/config/hosts.js';
import { writeJson, readJson } from '../src/onboard/json.js';
import { tempDir } from './helpers/temp-dir.js';

const tester = 't_aaaaaaaaaaaaaaaaaaaa';
const normal = 't_bbbbbbbbbbbbbbbbbbbb';
const target = 'attach.example-edge.test';
const domain = 'example-edge.test';
const alt = 'edge.example-edge.test';
const label = `e2e-x.${domain}`;

function setup(t, extra = {}) {
  const dataDir = tempDir(t);
  const txt = new Map();
  const resolver = {
    async resolveCname() { return [target]; },
    async resolve4() { return []; },
    async resolveTxt(name) { return txt.get(name) ?? []; },
  };
  const claims = createClaims({ dataDir, attachTarget: target, altAttachTarget: alt, edgePublicIp: '192.0.2.1', resolver,
    now: () => Date.UTC(2026, 0, 1), ...extra }, () => {});
  const mark = (ids) => writeJson('test_tenants.json', ids, 0o600, dataDir);
  async function activate(tid, host) {
    const c = claims.create(tid, { hostname: host, hostname_limit: 5 }).body;
    txt.set(c.dns.txt.name, [[c.dns.txt.value]]);
    return claims.verify(tid, host);
  }
  return { dataDir, claims, mark, activate, txt };
}

const code = (fn) => { try { fn(); } catch (e) { return e.code; } return 'no_error'; };

test('marked test tenant claims and verifies e2e-<label>.<attach-domain>; nothing is auto-verified', async (t) => {
  const h = setup(t);
  h.mark([tester]);
  const created = h.claims.create(tester, { hostname: label, hostname_limit: 5 });
  assert.equal(created.status, 201);
  assert.equal(created.body.status, 'pending');
  const unverified = await h.claims.verify(tester, label);
  assert.equal(unverified.verified, false);
  const result = await h.activate(tester, label);
  assert.equal(result.verified, true);
  assert.equal(result.status, 'active');
  assert.ok(readJson('tunnel_hosts.json', [], h.dataDir).includes(label));
  assert.equal(code(() => h.claims.create(tester, { hostname: 'e2e-' + 'a'.repeat(40) + '.' + domain, hostname_limit: 5 })), 'no_error');
});

test('unmarked tenants get reserved_hostname for e2e names and every name under the domain', (t) => {
  const h = setup(t);
  h.mark([tester]);
  for (const host of [label, `www.${domain}`, `app.${domain}`]) assert.equal(code(() => h.claims.create(normal, { hostname: host, hostname_limit: 5 })), 'reserved_hostname');
  assert.equal(code(() => h.claims.create(tester, { hostname: `app.${domain}`, hostname_limit: 5 })), 'reserved_hostname');
});

test('test tenant is still refused deeper names, apex, www, targets, lease and guardrails', (t) => {
  const h = setup(t);
  h.mark([tester]);
  const refused = [`a.e2e-x.${domain}`, domain, `www.${domain}`, target, alt, `e2e.${domain}`,`e2e-${'a'.repeat(41)}.${domain}`,
    `e2e-x.y.${domain}`,`e2e-x.${domain.replace('-', 'x-')}`, `xe2e-x.${domain}`, `e2e-x.${domain}.invalid`];
  for (const host of refused) assert.equal(code(() => h.claims.create(tester, { hostname: host, hostname_limit: 5 })), 'reserved_hostname', host);
  for (const guardrail of ENFORCE_DENYLIST) {
    const own = createClaims({ dataDir: h.dataDir, attachTarget: `attach.${guardrail.split('.').slice(-2).join('.')}`, altAttachTarget: alt, now: Date.now }, () => {});
    assert.equal(code(() => own.create(tester, { hostname: guardrail, hostname_limit: 5 })), 'reserved_hostname', guardrail);
    assert.equal(isTestLabelHost(guardrail, `attach.${guardrail.split('.').slice(-2).join('.')}`), false, guardrail);
  }
});

test('an existing legacy attachment on an e2e name blocks the test tenant', (t) => {
  const h = setup(t);
  h.mark([tester]);
  writeJson('attached_hosts.json', [{ hostname: label, status: 'active' }], 0o600, h.dataDir);
  assert.equal(code(() => h.claims.create(tester, { hostname: label, hostname_limit: 5 })), 'hostname_unavailable');
});

test('missing or malformed marking file means nobody', (t) => {
  const h = setup(t);
  assert.equal(testTenants(h.dataDir).size, 0);
  assert.equal(code(() => h.claims.create(tester, { hostname: label, hostname_limit: 5 })), 'reserved_hostname');
  const file = path.join(h.dataDir, 'test_tenants.json');
  for (const raw of ['not json', '{"a":1}', '"t_aaaaaaaaaaaaaaaaaaaa"', JSON.stringify([tester, 'someone@example.test']), JSON.stringify([tester, 7]), JSON.stringify(['T_AAAAAAAAAAAAAAAAAAAA'])]) {
    fs.writeFileSync(file, raw);
    assert.equal(testTenants(h.dataDir).size, 0, raw);
    assert.equal(code(() => h.claims.create(tester, { hostname: label, hostname_limit: 5 })), 'reserved_hostname', raw);
  }
});

test('unmarking refuses new verification but keeps an existing active claim', async (t) => {
  const h = setup(t);
  h.mark([tester]);
  const second = `e2e-y.${domain}`;
  await h.activate(tester, label);
  const pending = h.claims.create(tester, { hostname: second, hostname_limit: 5 }).body;
  h.txt.set(pending.dns.txt.name, [[pending.dns.txt.value]]);
  h.mark([]);
  await assert.rejects(h.claims.verify(tester, second), { code: 'reserved_hostname' });
  assert.equal(code(() => h.claims.create(tester, { hostname: `e2e-z.${domain}`, hostname_limit: 5 })), 'reserved_hostname');
  assert.equal(h.claims.get(tester, label).status, 'active');
  assert.equal((await h.claims.verify(tester, label)).status, 'active');
});

test('CLI helper writes test_tenants.json atomically with mode 0600', (t) => {
  const dir = tempDir(t);
  const file = path.join(dir, 'test_tenants.json');
  assert.deepEqual(editTestTenants('list', undefined, dir), { test_tenants: [] });
  assert.deepEqual(editTestTenants('add', tester, dir), { test_tenants: [tester] });
  assert.deepEqual(editTestTenants('add', tester, dir), { test_tenants: [tester] });
  editTestTenants('add', normal, dir);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, 'utf8')), [tester, normal]);
  assert.deepEqual(editTestTenants('remove', tester, dir), { test_tenants: [normal] });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(dir), ['test_tenants.json']);
  assert.throws(() => editTestTenants('add', 'not-a-tenant', dir), /invalid tenant id/);
  fs.writeFileSync(file, 'garbage');
  assert.throws(() => editTestTenants('add', tester, dir), /malformed/);
  assert.equal(fs.readFileSync(file, 'utf8'), 'garbage');
});

test('onboard CLI test-tenant command runs against DATA_DIR', (t) => {
  const dir = tempDir(t);
  const script = fileURLToPath(new URL('../scripts/onboard.js', import.meta.url));
  const run = (...args) => JSON.parse(execFileSync(process.execPath, [script, 'test-tenant', ...args], { env: { ...process.env, DATA_DIR: dir }, encoding: 'utf8' }));
  assert.deepEqual(run('add', tester), { test_tenants: [tester] });
  assert.deepEqual(run('list'), { test_tenants: [tester] });
  assert.equal(fs.statSync(path.join(dir, 'test_tenants.json')).mode & 0o777, 0o600);
  assert.deepEqual(run('remove', tester), { test_tenants: [] });
});

test('TLS ask approves a verified test-label claim, refuses unverified and everything else under the domain', async (t) => {
  const h = setup(t);
  h.mark([tester]);
  const ask = createTlsAsk({ tlsAskEnabled: true, liveVerify: false, dataDir: h.dataDir, attachTarget: target, altAttachTarget: alt, now: () => Date.UTC(2026, 0, 1) });
  const pendingHost = `e2e-p.${domain}`;
  h.claims.create(tester, { hostname: pendingHost, hostname_limit: 5 });
  assert.equal(ask(pendingHost).status, 404);
  await h.activate(tester, label);
  assert.equal(ask(label).status, 200);
  assert.equal(ask(pendingHost).status, 404);
  for (const host of [`app.${domain}`, `a.${label}`, domain, `www.${domain}`, target, alt]) assert.equal(ask(host).status, 404, host);
  // Operator attachments (no tenant) and malformed tenant ids under the domain stay refused.
  writeJson('attached_hosts.json', [{ hostname: `e2e-legacy.${domain}`, status: 'active' }, { hostname: `app.${domain}`, status: 'active' }], 0o600, h.dataDir);
  writeJson('tenant_hostnames.json', [
    { tenant_id: tester, hostname: `app.${domain}`, status: 'active', verified_at: new Date().toISOString() },
    { tenant_id: 'bad', hostname: `e2e-bad.${domain}`, status: 'active', verified_at: new Date().toISOString() },
  ], 0o600, h.dataDir);
  for (const host of [`e2e-legacy.${domain}`, `app.${domain}`, `e2e-bad.${domain}`, label]) assert.equal(ask(host).status, 404, host);
});

test('TLS ask: a verified test-label claim is approved, counts against its tenant cap, and static hosts stay exact', async (t) => {
  const h = setup(t);
  h.mark([tester]);
  const ask = createTlsAsk({ tlsAskEnabled: true, liveVerify: false, dataDir: h.dataDir, attachTarget: target, altAttachTarget: alt,
    now: () => Date.UTC(2026, 0, 1), tenantMaxPerHour: 2, staticHosts: [`static.${domain}`] });
  const other = `e2e-y.${domain}`;
  const third = `e2e-z.${domain}`;
  await h.activate(tester, label);
  await h.activate(tester, other);
  await h.activate(tester, third);
  assert.deepEqual([ask(label), ask(other)].map((r) => [r.status, r.reason]), [[200, 'approved_new'], [200, 'approved_new']]);
  const capped = ask(third);
  assert.deepEqual([capped.status, capped.reason], [429, 'approval_cap_tenant']);
  assert.equal(ask(label).reason, 'approved_repeat');
  assert.equal(ask(`static.${domain}`).status, 200);
  assert.equal(ask(`other.${domain}`).status, 404);
});

test('TLS ask requires the owner of an e2e name to still be a marked test tenant', async (t) => {
  const h = setup(t);
  h.mark([tester]);
  const make = (extra = {}) => createTlsAsk({ tlsAskEnabled: true, liveVerify: false, dataDir: h.dataDir, attachTarget: target,
    altAttachTarget: alt, now: () => Date.UTC(2026, 0, 1), ...extra });
  await h.activate(tester, label);
  assert.equal(make()(label).status, 200);
  // The active claim stays routed, but no certificate is issued once the marking is gone.
  h.mark([]);
  assert.equal(make()(label).status, 404);
  // Even with no reserved suffix covering the attach domain, an unmarked owner is refused.
  assert.equal(make({ reservedSuffixes: [] })(label).status, 404);
});

test('guardrail hosts and their subdomains are refused when claiming and never approved by TLS ask', (t) => {
  const h = setup(t);
  const now = new Date().toISOString();
  const records = [];
  for (const guardrail of ENFORCE_DENYLIST) {
    for (const host of [guardrail, `child.${guardrail}`]) {
      assert.equal(code(() => h.claims.create(normal, { hostname: host, hostname_limit: 5 })), 'reserved_hostname', host);
      records.push({ tenant_id: normal, hostname: host, status: 'active', verified_at: now });
    }
  }
  writeJson('tenant_hostnames.json', records, 0o600, h.dataDir);
  writeJson('attached_hosts.json', ENFORCE_DENYLIST.map((hostname) => ({ hostname, status: 'active' })), 0o600, h.dataDir);
  const ask = createTlsAsk({ tlsAskEnabled: true, liveVerify: false, dataDir: h.dataDir, attachTarget: target, altAttachTarget: alt,
    reservedSuffixes: [], staticHosts: ENFORCE_DENYLIST, now: () => Date.UTC(2026, 0, 1) });
  for (const { hostname } of records) assert.equal(ask(hostname).status, 404, hostname);
});
