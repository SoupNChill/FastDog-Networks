import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import WebSocket from 'ws';
import { _resetForTests, registerAgent, listAgents } from '../src/control/tunnels.js';
import { resetForTests } from '../src/lib/metrics.js';

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
    resetForTests();
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

  it('GET /health from loopback returns full details', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.ok(body.service, 'loopback should include service');
    assert.ok(body.version, 'loopback should include version');
    assert.ok(body.listen, 'loopback should include listen');
    assert.ok(body.routesFile, 'loopback should include routesFile');
    assert.ok('routeCount' in body, 'loopback should include routeCount');
    assert.ok('agents' in body, 'loopback should include agents');
    assert.ok(body.warning, 'loopback should include warning');
  });

  it('GET /health with X-Forwarded-For returns minimal response', async () => {
    const res = await fetch(`http://127.0.0.1:${port}/health`, {
      headers: { 'X-Forwarded-For': '203.0.113.42' },
    });
    const body = await res.json();
    assert.equal(body.ok, true);
    assert.ok(body.version, 'public should include version');
    assert.equal(Object.keys(body).length, 2, 'public should only have ok and version');
    assert.equal(body.listen, undefined, 'public should not include listen');
    assert.equal(body.service, undefined, 'public should not include service');
    assert.equal(body.routesFile, undefined, 'public should not include routesFile');
    assert.equal(body.agents, undefined, 'public should not include agents');
  });

  it('serves the marketing preview at /www/', async () => {
    const page = await fetch(`http://127.0.0.1:${port}/www/`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Fast by/);
    const style = await fetch(`http://127.0.0.1:${port}/www/css/site.css`);
    assert.equal(style.status, 200);
    assert.match(await style.text(), /#00D4FF/);
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

  it('GET /_fastdog/metrics includes registration and proxy counters', async () => {
    const before = await (await fetch(`http://127.0.0.1:${port}/_fastdog/metrics`)).json();
    assert.ok(before.registerCount >= 1);
    assert.ok(before.agentsRegistered >= 1);
    assert.equal(before.tunnelConnected, false);
    await new Promise((resolve, reject) => {
      http.get({ hostname: '127.0.0.1', port, path: '/test', headers: { Host: 'demo.fastdog.local' } }, (res) => {
        res.resume();
        res.on('end', resolve);
      }).on('error', reject);
    });
    const after = await (await fetch(`http://127.0.0.1:${port}/_fastdog/metrics`)).json();
    assert.equal(after.requestsProxied, before.requestsProxied + 1);
    assert.equal(after.requestsStatic, before.requestsStatic + 1);
    assert.equal(after.registerCount, before.registerCount);
  });

  it('counts a connected tunnel and tunnel requests', async () => {
    const id = listAgents().find((agent) => agent.hostname === 'tunnel.example.local').id;
    const ws = new WebSocket(`ws://127.0.0.1:${port}/_fastdog/tunnel?agentId=${id}&token=test-token`);
    await new Promise((resolve, reject) => {
      ws.once('message', resolve);
      ws.once('error', reject);
    });
    const connected = await (await fetch(`http://127.0.0.1:${port}/_fastdog/metrics`)).json();
    assert.equal(connected.tunnelConnected, true);
    assert.equal(connected.agentsConnected, 1);
    ws.close();
    await new Promise((resolve) => ws.once('close', resolve));
    const before = await (await fetch(`http://127.0.0.1:${port}/_fastdog/metrics`)).json();
    assert.equal(before.tunnelConnected, false);
    await new Promise((resolve, reject) => {
      http.get({ hostname: '127.0.0.1', port, path: '/test', headers: { Host: 'tunnel.example.local' } }, (res) => {
        res.resume();
        res.on('end', resolve);
      }).on('error', reject);
    });
    const after = await (await fetch(`http://127.0.0.1:${port}/_fastdog/metrics`)).json();
    assert.equal(after.requestsProxied, before.requestsProxied + 1);
    assert.equal(after.requestsTunnel, before.requestsTunnel + 1);
  });
});

describe('tunnel POST body forwarding (shared server)', () => {
  let server;
  let port;

  before(async () => {
    _resetForTests();
    resetForTests();
    process.env.NODE_ENV = 'test';
    process.env.EDGE_PORT = '0';
    process.env.AGENT_TOKEN = 'test-token';
    const mod = await import('../src/edge/server.js?postbody');
    await new Promise((resolve) => {
      mod.server.listen(0, '127.0.0.1', resolve);
    });
    server = mod.server;
    port = server.address().port;
  });

  after(async () => {
    _resetForTests();
    await new Promise((resolve) => server.close(resolve));
    delete process.env.NODE_ENV;
  });

  it('POST with JSON body is forwarded through tunnel', async () => {
    const reg = await fetch(`http://127.0.0.1:${port}/_fastdog/agents/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'body-test-agent',
        hostname: 'postbody.test.local',
        localUpstream: 'http://127.0.0.1:9999',
        token: 'test-token',
      }),
    });
    assert.equal(reg.status, 201);

    const agentId = (await reg.json()).id;
    const ws = new WebSocket(`ws://127.0.0.1:${port}/_fastdog/tunnel?agentId=${agentId}&token=test-token`);
    await new Promise((resolve, reject) => {
      ws.once('message', resolve);
      ws.once('error', reject);
    });

    const testBody = { email: 'test@example.com', password: 'secret123' };
    let receivedFrame = null;

    ws.on('message', (data) => {
      const msg = JSON.parse(String(data));
      if (msg.type === 'http_req') {
        receivedFrame = msg;
        ws.send(JSON.stringify({
          type: 'http_res',
          id: msg.id,
          status: 200,
          headers: { 'content-type': 'application/json' },
          bodyBase64: Buffer.from(JSON.stringify({ received: true })).toString('base64'),
        }));
      }
    });

    const res = await new Promise((resolve, reject) => {
      const reqData = JSON.stringify(testBody);
      const req = http.request({
        hostname: '127.0.0.1',
        port,
        path: '/api/auth/sign-in',
        method: 'POST',
        headers: {
          'Host': 'postbody.test.local',
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(reqData),
        },
      }, (res) => {
        let body = '';
        res.on('data', (chunk) => body += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body }));
      });
      req.on('error', reject);
      req.write(reqData);
      req.end();
    });

    assert.equal(res.status, 200, `Expected 200, got ${res.status}: ${res.body}`);
    const resBody = JSON.parse(res.body);
    assert.equal(resBody.received, true);

    assert.ok(receivedFrame, 'tunnel agent should receive HTTP frame');
    assert.equal(receivedFrame.method, 'POST');
    assert.equal(receivedFrame.path, '/api/auth/sign-in');
    assert.ok(receivedFrame.bodyBase64, 'frame should include body');
    const forwardedBody = JSON.parse(Buffer.from(receivedFrame.bodyBase64, 'base64').toString());
    assert.deepEqual(forwardedBody, testBody, 'forwarded body should match original');

    ws.close();
    await new Promise((resolve) => ws.once('close', resolve));
  });

  it('POST with non-JSON body is forwarded through tunnel', async () => {
    const reg = await fetch(`http://127.0.0.1:${port}/_fastdog/agents/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'form-test-agent',
        hostname: 'formdata.test.local',
        localUpstream: 'http://127.0.0.1:9999',
        token: 'test-token',
      }),
    });
    assert.equal(reg.status, 201);

    const agentId = (await reg.json()).id;
    const ws = new WebSocket(`ws://127.0.0.1:${port}/_fastdog/tunnel?agentId=${agentId}&token=test-token`);
    await new Promise((resolve, reject) => {
      ws.once('message', resolve);
      ws.once('error', reject);
    });

    const formBody = 'username=alice&password=secret';
    let receivedFrame = null;

    ws.on('message', (data) => {
      const msg = JSON.parse(String(data));
      if (msg.type === 'http_req') {
        receivedFrame = msg;
        ws.send(JSON.stringify({
          type: 'http_res',
          id: msg.id,
          status: 200,
          headers: { 'content-type': 'text/plain' },
          bodyBase64: Buffer.from('ok').toString('base64'),
        }));
      }
    });

    const res = await new Promise((resolve, reject) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port,
        path: '/login',
        method: 'POST',
        headers: {
          'Host': 'formdata.test.local',
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(formBody),
        },
      }, (res) => {
        let body = '';
        res.on('data', (chunk) => body += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body }));
      });
      req.on('error', reject);
      req.write(formBody);
      req.end();
    });

    assert.equal(res.status, 200, `Expected 200, got ${res.status}: ${res.body}`);

    assert.ok(receivedFrame, 'tunnel agent should receive HTTP frame');
    assert.equal(receivedFrame.method, 'POST');
    assert.ok(receivedFrame.bodyBase64, 'frame should include body');
    const forwardedBody = Buffer.from(receivedFrame.bodyBase64, 'base64').toString();
    assert.equal(forwardedBody, formBody, 'forwarded form body should match original');

    ws.close();
    await new Promise((resolve) => ws.once('close', resolve));
  });

  it('GET request without body works through tunnel', async () => {
    const reg = await fetch(`http://127.0.0.1:${port}/_fastdog/agents/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'get-test-agent',
        hostname: 'getreq.test.local',
        localUpstream: 'http://127.0.0.1:9999',
        token: 'test-token',
      }),
    });
    assert.equal(reg.status, 201);

    const agentId = (await reg.json()).id;
    const ws = new WebSocket(`ws://127.0.0.1:${port}/_fastdog/tunnel?agentId=${agentId}&token=test-token`);
    await new Promise((resolve, reject) => {
      ws.once('message', resolve);
      ws.once('error', reject);
    });

    let receivedFrame = null;

    ws.on('message', (data) => {
      const msg = JSON.parse(String(data));
      if (msg.type === 'http_req') {
        receivedFrame = msg;
        ws.send(JSON.stringify({
          type: 'http_res',
          id: msg.id,
          status: 200,
          headers: { 'content-type': 'application/json' },
          bodyBase64: Buffer.from(JSON.stringify({ status: 'healthy' })).toString('base64'),
        }));
      }
    });

    const res = await new Promise((resolve, reject) => {
      http.get({
        hostname: '127.0.0.1',
        port,
        path: '/api/health',
        headers: { 'Host': 'getreq.test.local' },
      }, (res) => {
        let body = '';
        res.on('data', (chunk) => body += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body }));
      }).on('error', reject);
    });

    assert.equal(res.status, 200, `Expected 200, got ${res.status}: ${res.body}`);
    const resBody = JSON.parse(res.body);
    assert.equal(resBody.status, 'healthy');

    assert.ok(receivedFrame, 'tunnel agent should receive HTTP frame');
    assert.equal(receivedFrame.method, 'GET');
    assert.equal(receivedFrame.bodyBase64, undefined, 'GET should have no body');

    ws.close();
    await new Promise((resolve) => ws.once('close', resolve));
  });
});
