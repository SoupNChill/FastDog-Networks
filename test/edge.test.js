import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { _resetForTests, registerAgent, listAgents } from '../src/control/tunnels.js';

describe('tunnel registry', () => {
  before(() => _resetForTests());
  after(() => _resetForTests());

  it('registers agent with token', () => {
    const r = registerAgent({
      name: 't1',
      hostname: 'demo.fastdog.local',
      localUpstream: 'http://127.0.0.1:9999',
      token: 'secret',
      expectedToken: 'secret',
    });
    assert.ok(r.id);
    assert.equal(r.hostname, 'demo.fastdog.local');
    assert.equal(listAgents().length, 1);
  });

  it('rejects bad token', () => {
    assert.throws(
      () =>
        registerAgent({
          hostname: 'x.local',
          localUpstream: 'http://127.0.0.1:1',
          token: 'nope',
          expectedToken: 'secret',
        }),
      /unauthorized/,
    );
  });
});

describe('health endpoint (live server)', () => {
  let server;
  let port;

  before(async () => {
    process.env.NODE_ENV = 'test';
    process.env.EDGE_PORT = '0';
    process.env.AGENT_TOKEN = 'test-token';
    // dynamic import after env
    const mod = await import('../src/edge/server.js');
    await new Promise((resolve) => {
      mod.server.listen(0, '127.0.0.1', resolve);
    });
    server = mod.server;
    port = server.address().port;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    delete process.env.NODE_ENV;
  });

  it('GET /health returns ok', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.equal(body.service, 'fastdog-edge');
  });

  it('GET /_fastdog/routes returns config', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/_fastdog/routes`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.routes['demo.fastdog.local']);
  });

  it('DNS list zones includes trysummitlease.com', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/_fastdog/dns/zones`);
    const body = await res.json();
    assert.ok(body.zones.includes('trysummitlease.com'));
  });

  it('agent register + list', async () => {
    const reg = await fetch(`http://127.0.0.1:${port}/_fastdog/agents/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'test-agent',
        hostname: 'tunnel.example.local',
        localUpstream: 'http://127.0.0.1:9999',
        token: 'test-token',
      }),
    });
    assert.equal(reg.status, 201);
    const agents = await (await fetch(`http://127.0.0.1:${port}/_fastdog/agents`)).json();
    assert.ok(agents.agents.some((a) => a.hostname === 'tunnel.example.local'));
  });
});
