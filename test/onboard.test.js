import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createZone, issueCredential, mapHost } from '../src/onboard/store.js';
import { readZone } from '../src/dns/store.js';
import { loadRoutes, ROOT } from '../src/lib/config.js';
import { registerAgent, _resetForTests } from '../src/control/tunnels.js';

describe('stranger onboarding', () => {
  let tmp;
  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-onboard-'));
    process.env.ZONES_DIR = path.join(tmp, 'zones');
    process.env.DATA_DIR = path.join(tmp, 'data');
  });
  after(() => {
    _resetForTests();
    delete process.env.ZONES_DIR;
    delete process.env.DATA_DIR;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('creates an authoritative zone without overwriting it', () => {
    const result = createZone({ zone: 'stranger.example', edge_ip: '192.0.2.10' });
    assert.equal(result.ns.length, 2);
    const records = readZone('stranger.example').records;
    assert.deepEqual(records.map((r) => r.type), ['SOA', 'NS', 'NS', 'A']);
    assert.match(records[0].content, /ns1\.fastdognetworks\.com\./);
    assert.throws(() => createZone({ zone: 'stranger.example' }), /zone_exists/);
  });

  it('issues a credential accepted for its agent hostname', () => {
    const { token } = issueCredential({ name: 'new-agent', hostname: 'app.stranger.example' });
    assert.ok(token.length >= 64);
    assert.ok(registerAgent({ hostname: 'app.stranger.example', localUpstream: 'http://127.0.0.1:9999', token, expectedToken: 'master' }).id);
    assert.throws(() => registerAgent({ hostname: 'other.stranger.example', localUpstream: 'http://127.0.0.1:9999', token, expectedToken: 'master' }), /unauthorized/);
    const file = path.join(tmp, 'data', 'agent-credentials.json');
    assert.ok(!fs.readFileSync(file, 'utf8').includes(token));
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  });

  it('maps a host to the edge and merges tunnel host routes', () => {
    const oldSerial = Number(readZone('stranger.example').records[0].content.split(' ')[2]);
    mapHost({ zone: 'stranger.example', hostname: 'app.stranger.example', origin_hint: 'http://127.0.0.1:8080' });
    mapHost({ zone: 'stranger.example', hostname: 'app.stranger.example' });
    assert.equal(readZone('stranger.example').records.filter((r) => r.name === 'app' && r.type === 'A').length, 1);
    assert.ok(Number(readZone('stranger.example').records[0].content.split(' ')[2]) > oldSerial);
    assert.ok(loadRoutes(path.join(ROOT, 'config/routes.yaml')).tunnelHosts.has('app.stranger.example'));
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(tmp, 'data', 'tunnel_hosts.json'))), ['app.stranger.example']);
  });

  it('serves authenticated onboarding API and reloads mapped hosts', async () => {
    process.env.NODE_ENV = 'test';
    process.env.AGENT_TOKEN = 'onboard-test-master';
    const { server } = await import('../src/edge/server.js');
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const post = (url, body, token = 'onboard-test-master') => fetch(`${base}${url}`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-fastdog-token': token }, body: JSON.stringify(body) });
    try {
      assert.equal((await post('/_fastdog/onboard/zones', { zone: 'api.example' }, 'wrong')).status, 401);
      assert.equal((await post('/_fastdog/onboard/zones', { zone: 'api.example' })).status, 201);
      const issued = await (await post('/_fastdog/onboard/credentials', { hostname: 'web.api.example' })).json();
      const registered = await post('/_fastdog/agents/register', { hostname: 'web.api.example', localUpstream: 'http://127.0.0.1:8080' }, issued.token);
      assert.equal(registered.status, 201);
      assert.equal((await post('/_fastdog/onboard/hosts', { zone: 'api.example', hostname: 'web.api.example' })).status, 201);
      const routes = await (await fetch(`${base}/_fastdog/routes`)).json();
      assert.ok(routes.tunnelHosts.includes('web.api.example'));
      const instructions = await fetch(`${base}/_fastdog/onboard/zones/api.example/ns-instructions`, { headers: { 'x-fastdog-token': 'onboard-test-master' } });
      assert.equal(instructions.status, 200);
    } finally {
      await new Promise((resolve) => server.close(resolve));
      delete process.env.NODE_ENV;
      delete process.env.AGENT_TOKEN;
    }
  });
});
