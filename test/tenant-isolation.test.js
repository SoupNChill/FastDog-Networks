import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { internalFile, internalHarness, hostPath, fakeSecret } from './helpers/internal.js';
import { tenants, acceptedHosts, rejectedClaims, attachTarget } from './helpers/fixtures.js';
import { expectError, jsonRequest } from './helpers/http.js';

const skip = existsSync(internalFile) ? false : 'lane A not merged: internal server absent';
const endpoints = [['GET', ''], ['POST', '/verify'], ['POST', '/credentials/rotate'], ['GET', '/agent'], ['DELETE', '']];

test('every other tenant sees exactly hostname_not_found for every valid awkward host', { skip }, async (t) => {
  for (const owner of tenants) for (const [input, host] of acceptedHosts) for (const state of ['pending', 'active']) {
    await t.test(`${owner} ${JSON.stringify(input)} ${state}`, async (t) => {
      const h = await internalHarness(t);
      const claim = await h.create(owner, input);
      assert.equal(claim.status, 201);
      assert.equal(claim.body.hostname, host);
      if (state === 'active') {
        h.prove(claim.body);
        assert.equal((await h.request(hostPath(owner, input, '/verify'), { method: 'POST' })).body.verified, true);
      }
      h.agents.set(host, { hostname: host, ws: { readyState: 1 }, localUpstream: 'http://origin.example.test',
        registeredAt: new Date(h.now()).toISOString(), lastSeen: new Date(h.now()).toISOString() });
      for (const other of tenants.filter((tid) => tid !== owner)) {
        const list = await h.request(hostPath(other));
        assert.equal(list.status, 200);
        assert.deepEqual(list.body, { hostnames: [] });
        for (const [method, suffix] of endpoints) {
          const response = await h.request(hostPath(other, input, suffix), { method });
          expectError(response, 404, 'hostname_not_found');
          assert.ok(!response.text.includes(claim.body.dns.txt.value));
        }
        const competing = await h.create(other, input);
        if (state === 'active') expectError(competing, 409, 'hostname_unavailable');
        else {
          assert.equal(competing.status, 201);
          assert.notEqual(competing.body.dns.txt.value, claim.body.dns.txt.value);
        }
      }
      assert.equal((await h.request(hostPath(owner, host))).body.status, state);
      assert.deepEqual(h.closed, []);
    });
  }
});

test('invalid and reserved awkward inputs cannot create claims for any tenant', { skip }, async (t) => {
  const h = await internalHarness(t);
  for (const tid of tenants) for (const [host, error] of rejectedClaims) {
    expectError(await h.create(tid, host), 400, error);
  }
  for (const tid of tenants) assert.deepEqual((await h.request(hostPath(tid))).body, { hostnames: [] });
});

test('three pending claims coexist; first proof wins, losers cannot detach the owner', { skip }, async (t) => {
  const h = await internalHarness(t);
  const host = 'app.example.com';
  const claims = [];
  for (const tid of tenants) {
    const created = await h.create(tid, host);
    assert.equal(created.status, 201);
    assert.match(created.body.dns.txt.value, /^fd-verify=[a-f0-9]{32}$/);
    claims.push(created.body);
    const repeat = await h.create(tid, 'App.Example.COM.');
    assert.equal(repeat.status, 200);
    assert.deepEqual(repeat.body, created.body);
  }
  assert.equal(new Set(claims.map((claim) => claim.dns.txt.value)).size, 3);
  h.prove(claims[0]);
  const wrongProof = await h.request(hostPath(tenants[1], host, '/verify'), { method: 'POST' });
  assert.equal(wrongProof.body.verified, false);
  assert.equal(wrongProof.body.checks.ownership.error, 'txt_mismatch');
  const winner = await h.request(hostPath(tenants[0], host, '/verify'), { method: 'POST' });
  assert.equal(winner.body.verified, true);
  assert.ok(winner.body.credential);
  for (const tid of tenants.slice(1)) {
    expectError(await h.request(hostPath(tid, host, '/verify'), { method: 'POST' }), 409, 'hostname_unavailable');
    // A losing tenant can delete its own pending claim, but never the active owner's mapping.
    assert.equal((await h.request(hostPath(tid, host), { method: 'DELETE' })).status, 200);
    expectError(await h.request(hostPath(tid, host), { method: 'DELETE' }), 404, 'hostname_not_found');
    assert.equal((await h.request('/tls/ask?domain=app.example.com')).status, 200);
    assert.deepEqual(h.closed, []);
  }
  for (const suffix of ['', '/verify', '/agent']) {
    const response = await h.request(hostPath(tenants[0], host, suffix), { method: suffix === '/verify' ? 'POST' : 'GET' });
    assert.equal(response.status, 200);
    assert.equal(response.body.credential, undefined);
    assert.ok(!response.text.includes(winner.body.credential.token));
    assert.ok(!response.text.includes(claims[0].dns.txt.value));
    assert.equal(response.body.localUpstream, undefined);
  }
});

test('concurrent valid proofs cannot activate more than one owner', { skip }, async (t) => {
  const h = await internalHarness(t);
  const host = 'race.example.com';
  const claims = await Promise.all(tenants.map((tid) => h.create(tid, host)));
  for (const claim of claims) assert.equal(claim.status, 201);
  h.resolver.set('CNAME', host, [attachTarget]);
  h.resolver.set('TXT', `_fastdog-challenge.${host}`, claims.map((claim) => [claim.body.dns.txt.value]));
  const results = await Promise.all(tenants.map((tid) => h.request(hostPath(tid, host, '/verify'), { method: 'POST' })));
  assert.equal(results.filter((result) => result.body.verified === true).length, 1);
  for (const result of results.filter((result) => result.status !== 200)) expectError(result, 409, 'hostname_unavailable');
  assert.equal(results.filter((result) => result.status === 409).length, 2);
});

test('suffix hosts are distinct records and TXT proof cannot replay after detach', { skip }, async (t) => {
  const h = await internalHarness(t);
  const hosts = ['app.example.com', 'myapp.example.com', 'x.app.example.com'];
  for (let i = 0; i < hosts.length; i++) await h.activate(tenants[i], hosts[i]);
  for (let i = 0; i < hosts.length; i++) {
    const list = await h.request(hostPath(tenants[i]));
    assert.deepEqual(list.body.hostnames.map((item) => item.hostname), [hosts[i]]);
  }
  assert.equal((await h.request(hostPath(tenants[0], hosts[0]), { method: 'DELETE' })).status, 200);
  const fresh = await h.create(tenants[1], hosts[0]);
  assert.equal(fresh.status, 201);
  const replay = await h.request(hostPath(tenants[1], hosts[0], '/verify'), { method: 'POST' });
  assert.equal(replay.body.verified, false);
  assert.equal(replay.body.checks.ownership.error, 'txt_mismatch');
});

test('internal API accepts only the portal key; malformed tenant segments fail closed', { skip }, async (t) => {
  const h = await internalHarness(t);
  for (const headers of [{}, { 'x-fastdog-portal-key': h.agentToken }, { 'x-fastdog-token': h.agentToken },
    { 'x-fastdog-portal-key': fakeSecret() }]) {
    expectError(await jsonRequest(h.server, hostPath(tenants[0]), { headers }), 401, 'unauthorized');
  }
  assert.equal((await h.request(hostPath(tenants[0]))).status, 200);
  const badTenants = ['..', '%2e%2e', '%2F', `${tenants[0]}%2F..`, `${tenants[0]}%252f`, tenants[0].toUpperCase(),
    tenants[0].slice(0, -1), `${tenants[0]}a`, `t_${'1'.repeat(20)}`, `t_${'8'.repeat(20)}`];
  for (const tid of badTenants) for (const [method, suffix] of endpoints) {
    expectError(await h.request(hostPath(tid, 'app.example.com', suffix), { method }), 400, 'invalid_tenant');
  }
  for (const tid of badTenants) {
    expectError(await h.request(hostPath(tid)), 400, 'invalid_tenant');
    expectError(await h.create(tid, 'app.example.com'), 400, 'invalid_tenant');
  }
});

test('legacy active attachments cannot be claimed by tenants', { skip }, async (t) => {
  const h = await internalHarness(t);
  writeFileSync(join(h.dataDir, 'attached_hosts.json'), JSON.stringify([
    { hostname: 'legacy.example.com', status: 'active', created_at: new Date(h.now()).toISOString() },
  ]));
  for (const tid of tenants) expectError(await h.create(tid, 'legacy.example.com'), 409, 'hostname_unavailable');
});

test('issued credentials are host-bound, operator keys are barred, rotate and detach revoke', { skip }, async (t) => {
  const h = await internalHarness(t);
  // Existing registry/store use DATA_DIR; scope it to this test's isolated store.
  const previous = process.env.DATA_DIR;
  process.env.DATA_DIR = h.dataDir;
  t.after(() => { if (previous === undefined) delete process.env.DATA_DIR; else process.env.DATA_DIR = previous; });
  const registry = await import('../src/control/tunnels.js');
  registry._resetForTests();
  t.after(() => registry._resetForTests());
  const first = await h.activate(tenants[0], 'app.example.com');
  await h.activate(tenants[1], 'myapp.example.com');
  const register = (token, hostname) => registry.registerAgent({
    token, hostname, expectedToken: h.agentToken, localUpstream: 'http://origin.example.test',
  });
  const denied = (token, host) => assert.throws(() => register(token, host), (error) => error.status === 401 && error.message === 'unauthorized');
  assert.equal(register(first.credential.token, first.hostname).hostname, first.hostname);
  denied(first.credential.token, 'myapp.example.com');
  for (const host of ['app.example.com', 'myapp.example.com']) {
    denied(h.agentToken, host);
    denied(h.portalKey, host);
  }
  const rotated = await h.request(hostPath(tenants[0], first.hostname, '/credentials/rotate'), { method: 'POST' });
  assert.equal(rotated.status, 200);
  assert.notEqual(rotated.body.credential.token, first.credential.token);
  denied(first.credential.token, first.hostname);
  assert.equal(register(rotated.body.credential.token, first.hostname).hostname, first.hostname);
  assert.ok(h.closed.includes(first.hostname));
  assert.equal((await h.request(hostPath(tenants[0], first.hostname), { method: 'DELETE' })).status, 200);
  denied(rotated.body.credential.token, first.hostname);
  assert.equal(h.closed.filter((host) => host === first.hostname).length, 2);
  const saved = readFileSync(join(h.dataDir, 'agent-credentials.json'), 'utf8');
  assert.ok(!saved.includes(first.credential.token));
  assert.ok(!saved.includes(rotated.body.credential.token));
  const logText = JSON.stringify(h.logs);
  for (const secret of [h.portalKey, h.agentToken, first.credential.token, rotated.body.credential.token]) assert.ok(!logText.includes(secret));
});
