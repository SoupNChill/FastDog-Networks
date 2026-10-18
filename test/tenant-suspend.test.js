import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { internalHarness, hostPath, fakeSecret } from './helpers/internal.js';
import { tenants } from './helpers/fixtures.js';
import { expectError, jsonRequest } from './helpers/http.js';
import { createClaims } from '../src/internal/claims.js';

const suspendPath = (tid) => `/internal/v1/tenants/${tid}/suspend`;

test('tenant suspension requires portal authentication, valid tenant and POST', async (t) => {
  const h = await internalHarness(t);
  for (const endpoint of ['suspend', 'release']) {
    const path = (tid) => suspendPath(tid).replace('/suspend', '/' + endpoint);
    for (const headers of [{}, { 'x-fastdog-portal-key': h.agentToken }, { 'x-fastdog-portal-key': fakeSecret() }]) {
      expectError(await jsonRequest(h.server, path(tenants[0]), { method: 'POST', headers }), 401, 'unauthorized');
    }
    for (const tid of ['invalid', tenants[0].toUpperCase(), '%2F', `${tenants[0]}a`]) {
      expectError(await h.request(path(tid), { method: 'POST' }), 400, 'invalid_tenant');
    }
    expectError(await h.request(path(tenants[0])), 405, 'method_not_allowed');
  }
  assert.deepEqual((await h.request(suspendPath(tenants[0]), { method: 'POST' })).body,
    { tenant_id: tenants[0], suspended: 0, hostnames: [] });
  assert.equal(h.logs.at(-1)[0].route, '/internal/v1/tenants/:tid/suspend');
});

test('suspension removes access once, preserves other owners and requires administrative release', async (t) => {
  const h = await internalHarness(t);
  const hosts = ['one.example.test', 'two.example.test'];
  for (const host of hosts) await h.activate(tenants[0], host);
  await h.activate(tenants[1], 'other.example.test');
  await h.create(tenants[0], 'other.example.test').then((r) => expectError(r, 409, 'hostname_unavailable'));
  await h.create(tenants[0], 'pending.example.test');
  await h.create(tenants[0], 'shared.example.test');
  await h.activate(tenants[1], 'shared.example.test');
  const read = (file) => JSON.parse(readFileSync(join(h.dataDir, file), 'utf8'));
  const write = (file, value) => writeFileSync(join(h.dataDir, file), JSON.stringify(value));
  write('attached_hosts.json', [{ hostname: 'legacy.example.test', status: 'active' }]);
  write('tunnel_hosts.json', [...read('tunnel_hosts.json'), 'legacy.example.test']);
  const otherCredentials = read('agent-credentials.json').filter((c) => c.tenant_id === tenants[1]);
  let changes = 0;
  h.server.on('routesChanged', () => changes++);
  // Active records retain an old pending expiry; suspension must not discard them.
  h.clock.advance(2 * 86400000);
  const response = await h.request(suspendPath(tenants[0]), { method: 'POST' });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body, { tenant_id: tenants[0], suspended: 2, hostnames: hosts });
  assert.equal(changes, 1);
  assert.deepEqual(h.closed, hosts);
  assert.deepEqual(read('agent-credentials.json'), otherCredentials);
  assert.deepEqual(read('tunnel_hosts.json'), ['other.example.test', 'shared.example.test', 'legacy.example.test']);
  assert.equal(read('tenant_hostnames.json').filter((c) => c.tenant_id === tenants[0]).length, 2);
  const claims = createClaims(h, () => {});
  for (const host of hosts) {
    assert.equal(claims.ask(host), false);
    assert.equal((await h.request(`/tls/ask?domain=${host}`)).status, 404);
    assert.equal((await h.request(hostPath(tenants[0], host))).body.status, 'suspended');
    for (const suffix of ['/agent', '/status']) expectError(await h.request(hostPath(tenants[0], host, suffix)), 409, 'not_active');
  }
  for (const host of ['other.example.test', 'shared.example.test', 'legacy.example.test']) assert.equal(claims.ask(host), true);
  const files = ['tenant_hostnames.json', 'agent-credentials.json', 'tunnel_hosts.json', 'attached_hosts.json'];
  const snapshot = () => files.map((file) => [readFileSync(join(h.dataDir, file), 'utf8'), statSync(join(h.dataDir, file)).mtimeMs]);
  const before = snapshot();
  assert.deepEqual((await h.request(suspendPath(tenants[0]), { method: 'POST' })).body,
    { tenant_id: tenants[0], suspended: 0, hostnames: [] });
  assert.deepEqual(snapshot(), before);
  assert.equal(changes, 1);
  assert.deepEqual(h.closed, hosts);
  h.clock.advance(2 * 86400000);
  const verified = await h.request(hostPath(tenants[0], hosts[0], '/verify'), { method: 'POST' });
  expectError(verified, 409, 'administratively_suspended');
  expectError(await h.request(hostPath(tenants[0], hosts[0]), { method: 'DELETE' }), 409, 'administratively_suspended');
  const release = suspendPath(tenants[0]).replace('/suspend', '/release');
  assert.deepEqual((await h.request(release, { method: 'POST' })).body, { tenant_id: tenants[0], released: 2 });
  assert.deepEqual((await h.request(release, { method: 'POST' })).body, { tenant_id: tenants[0], released: 0 });
  await h.activate(tenants[1], hosts[0]);
});

test('claims suspension removes pending records and retains active records until release', async (t) => {
  const { tempDir } = await import('./helpers/temp-dir.js');
  const { fixedClock } = await import('./helpers/clock.js');
  const { fakeResolver } = await import('./helpers/resolver.js');
  const { attachTarget, altAttachTarget, edgePublicIp, reservedSuffixes } = await import('./helpers/fixtures.js');
  const clock = fixedClock();
  const dataDir = tempDir(t);
  const resolver = fakeResolver();
  const closed = [];
  let changes = 0;
  const claims = createClaims({ dataDir, now: clock.now, resolver, attachTarget, altAttachTarget, edgePublicIp,
    reservedSuffixes, registry: { closeHost: (host) => closed.push(host) } }, () => changes++);
  const host = 'unit.example.test';
  const created = claims.create(tenants[0], { hostname: host, hostname_limit: 10 });
  resolver.set('CNAME', host, [attachTarget]);
  resolver.set('TXT', `_fastdog-challenge.${host}`, [[created.body.dns.txt.value]]);
  await claims.verify(tenants[0], host);
  claims.create(tenants[0], { hostname: 'pending.example.test', hostname_limit: 10 });
  clock.advance(2 * 86400000);
  changes = 0;
  closed.length = 0;
  assert.deepEqual(claims.suspendTenant(tenants[0]), { tenant_id: tenants[0], suspended: 1, hostnames: [host] });
  assert.equal(changes, 1);
  assert.deepEqual(closed, [host]);
  assert.equal(claims.ask(host), false);
  assert.throws(() => claims.agent(tenants[0], host), { code: 'not_active' });
  assert.equal(claims.list(tenants[0]).hostnames.length, 1);
  for (const file of ['agent-credentials.json', 'tunnel_hosts.json']) {
    assert.deepEqual(JSON.parse(readFileSync(join(dataDir, file), 'utf8')), []);
  }
  assert.deepEqual(claims.suspendTenant(tenants[0]), { tenant_id: tenants[0], suspended: 0, hostnames: [] });
  assert.equal(changes, 1);
  assert.deepEqual(closed, [host]);
  clock.advance(2 * 86400000);
  await assert.rejects(claims.verify(tenants[0], host), { code: 'administratively_suspended' });
  assert.equal(claims.ask(host), false);
});

async function unit(t) {
  const { tempDir } = await import('./helpers/temp-dir.js');
  const { fixedClock } = await import('./helpers/clock.js');
  const { fakeResolver } = await import('./helpers/resolver.js');
  const fixtures = await import('./helpers/fixtures.js');
  const clock = fixedClock(), resolver = fakeResolver(), dataDir = tempDir(t), closed = [];
  const options = { ...fixtures, dataDir, resolver, now: clock.now, registry: { closeHost: (host) => closed.push(host) } };
  const claims = createClaims(options, () => {});
  const read = (file) => JSON.parse(readFileSync(join(dataDir, file), 'utf8'));
  const write = (file, value) => writeFileSync(join(dataDir, file), JSON.stringify(value));
  const create = (tid, host) => claims.create(tid, { hostname: host, hostname_limit: 10 });
  const prove = (claim) => {
    resolver.set('CNAME', claim.body.hostname, [fixtures.attachTarget]);
    resolver.set('TXT', '_fastdog-challenge.' + claim.body.hostname, [[claim.body.dns.txt.value]]);
  };
  return { claims, options, clock, resolver, dataDir, closed, read, write, create, prove };
}

test('administrative reservations block create and verify indefinitely, release only administrative claims', async (t) => {
  const h = await unit(t), host = 'reserved.example.test';
  const contender = h.create(tenants[1], host);
  h.prove(h.create(tenants[0], host));
  await h.claims.verify(tenants[0], host);
  h.claims.suspendTenant(tenants[0]);
  h.prove(contender);
  await assert.rejects(h.claims.verify(tenants[1], host), { code: 'hostname_unavailable' });
  h.clock.advance(25 * 3600000);
  assert.throws(() => h.create(tenants[1], host), { code: 'hostname_unavailable' });
  // A surviving DNS-suspended contender still cannot verify after 25 hours.
  const records = h.read('tenant_hostnames.json');
  Object.assign(records.find((c) => c.tenant_id === tenants[1]), {
    status: 'suspended', expires_at: new Date(h.clock.now() + 86400000).toISOString(),
  });
  h.write('tenant_hostnames.json', records);
  const restarted = createClaims(h.options, () => {});
  await assert.rejects(restarted.verify(tenants[1], host), { code: 'hostname_unavailable' });
  assert.deepEqual(restarted.releaseTenant(tenants[1]), { tenant_id: tenants[1], released: 0 });
  h.create(tenants[0], 'pending.example.test');
  assert.deepEqual(restarted.releaseTenant(tenants[0]), { tenant_id: tenants[0], released: 1 });
  assert.equal(restarted.list(tenants[0]).hostnames.length, 1);
  assert.equal(restarted.create(tenants[1], { hostname: host, hostname_limit: 10 }).status, 200);
  assert.equal((await restarted.verify(tenants[1], host)).verified, true);
});

test('in-flight DNS-suspended verification cannot cross administrative suspension', async (t) => {
  const h = await unit(t), host = 'race.example.test';
  const claim = h.create(tenants[0], host);
  h.prove(claim);
  await h.claims.verify(tenants[0], host);
  const records = h.read('tenant_hostnames.json');
  Object.assign(records[0], { status: 'suspended', expires_at: new Date(h.clock.now() + 86400000).toISOString() });
  h.write('tenant_hostnames.json', records);
  let finish, started;
  const entered = new Promise((resolve) => { started = resolve; });
  h.resolver.set('TXT', '_fastdog-challenge.' + host, () => { started(); return new Promise((resolve) => { finish = resolve; }); });
  const verification = h.claims.verify(tenants[0], host);
  await entered;
  h.claims.suspendTenant(tenants[0]);
  assert.equal(h.read('tenant_hostnames.json')[0].suspension_generation, 1);
  finish([[claim.body.dns.txt.value]]);
  await assert.rejects(verification, { code: 'administratively_suspended' });
  assert.equal(h.claims.ask(host), false);
  assert.deepEqual(h.read('agent-credentials.json'), []);
  assert.deepEqual(h.read('tunnel_hosts.json'), []);
});

test('suspend drops expired DNS claims and preserves another active owner of a DNS-suspended host', async (t) => {
  const h = await unit(t), host = 'overlap.example.test';
  h.create(tenants[0], host);
  h.create(tenants[0], 'expired.example.test');
  const records = h.read('tenant_hostnames.json');
  for (const c of records) c.status = 'suspended';
  records[1].expires_at = new Date(h.clock.now() - 1).toISOString();
  h.write('tenant_hostnames.json', records);
  h.prove(h.create(tenants[1], host));
  await h.claims.verify(tenants[1], host);
  const credentials = h.read('agent-credentials.json');
  h.closed.length = 0;
  h.claims.suspendTenant(tenants[0]);
  assert.deepEqual(h.read('agent-credentials.json'), credentials);
  assert.deepEqual(h.read('tunnel_hosts.json'), [host]);
  assert.deepEqual(h.closed, []);
  assert.equal(h.claims.ask(host), true);
  assert.equal(h.claims.list(tenants[0]).hostnames.length, 1);
  assert.equal(h.create(tenants[1], 'expired.example.test').status, 201);
  h.claims.releaseTenant(tenants[0]);
  assert.deepEqual(h.read('agent-credentials.json'), credentials);
  assert.deepEqual(h.read('tunnel_hosts.json'), [host]);
});

for (const failedFile of ['agent-credentials.json', 'tunnel_hosts.json']) test('suspension retry after failed write: ' + failedFile, async (t) => {
  const fs = (await import('node:fs')).default;
  const h = await unit(t), host = 'retry.example.test';
  h.prove(h.create(tenants[0], host));
  await h.claims.verify(tenants[0], host);
  const rename = fs.renameSync;
  const mock = t.mock.method(fs, 'renameSync', (from, to) => {
    if (to === join(h.dataDir, failedFile)) throw new Error('injected write failure');
    return rename(from, to);
  });
  assert.throws(() => h.claims.suspendTenant(tenants[0]), /injected write failure/);
  assert.equal(h.claims.ask(host), false);
  await assert.rejects(h.claims.verify(tenants[0], host), { code: 'administratively_suspended' });
  mock.mock.restore();
  h.claims.suspendTenant(tenants[0]);
  assert.deepEqual(h.read('agent-credentials.json'), []);
  assert.deepEqual(h.read('tunnel_hosts.json'), []);
  assert.ok(h.closed.includes(host));
});
