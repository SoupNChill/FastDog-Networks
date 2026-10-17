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
  for (const headers of [{}, { 'x-fastdog-portal-key': h.agentToken }, { 'x-fastdog-portal-key': fakeSecret() }]) {
    expectError(await jsonRequest(h.server, suspendPath(tenants[0]), { method: 'POST', headers }), 401, 'unauthorized');
  }
  for (const tid of ['invalid', tenants[0].toUpperCase(), '%2F', `${tenants[0]}a`]) {
    expectError(await h.request(suspendPath(tid), { method: 'POST' }), 400, 'invalid_tenant');
  }
  expectError(await h.request(suspendPath(tenants[0])), 405, 'method_not_allowed');
  assert.deepEqual((await h.request(suspendPath(tenants[0]), { method: 'POST' })).body,
    { tenant_id: tenants[0], suspended: 0, hostnames: [] });
  assert.equal(h.logs.at(-1)[0].route, '/internal/v1/tenants/:tid/suspend');
});

test('suspension removes access once, preserves other owners and allows later verification', async (t) => {
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
  assert.equal(verified.status, 200);
  assert.equal(verified.body.verified, true);
  assert.ok(verified.body.credential);
  assert.equal(claims.ask(hosts[0]), true);
  assert.equal((await h.request(hostPath(tenants[0], hosts[0], '/agent'))).status, 200);
});

test('claims suspension removes pending records and retains expired active records for re-verification', async (t) => {
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
  assert.equal((await claims.verify(tenants[0], host)).verified, true);
  assert.equal(claims.ask(host), true);
});
