import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { equalToken, operatorAuth } from '../src/control/auth.js';

const fake = () => `fake-${randomBytes(32).toString('hex')}`;
test('operator middleware accepts header or JSON token and rejects portal credentials', () => {
  const operator = fake();
  const portal = fake();
  const middleware = operatorAuth(operator);
  for (const [headers, body, expected] of [
    [{}, {}, 401], [{ 'x-fastdog-token': portal }, {}, 401], [{ 'x-fastdog-portal-key': portal }, {}, 401],
    [{ 'x-fastdog-token': operator }, {}, 200], [{}, { token: operator }, 200], [{}, { token: portal }, 401],
  ]) {
    let status = 200;
    let response;
    let called = false;
    middleware({ headers, body }, { status(code) { status = code; return this; }, json(value) { response = value; } }, () => { called = true; });
    assert.equal(status, expected);
    assert.equal(called, expected === 200);
    if (expected === 401) assert.deepEqual(response, { error: 'unauthorized' });
  }
  assert.equal(equalToken('', ''), false);
  assert.equal(equalToken([], operator), false);
  assert.equal(equalToken(operator, `${operator}extra`), false);
});

test('public control routes require operator auth; open endpoints retain their behavior', async (t) => {
  const directory = fs.mkdtempSync(path.join(process.cwd(), 'test/.control-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const operator = fake();
  const portal = fake();
  Object.assign(process.env, { NODE_ENV: 'test', AGENT_TOKEN: operator, DATA_DIR: directory, ZONES_DIR: path.join(directory, 'zones'),
    STATUS_DATA_DIR: directory, INTERNAL_ENABLED: '0', BILLING_ENABLED: 'false' });
  let mod;
  try { mod = await import('../src/edge/server.js'); }
  catch (error) {
    if (error.code !== 'ERR_MODULE_NOT_FOUND' && error.code !== 'MODULE_NOT_FOUND') throw error;
    t.skip('Existing edge dependencies are absent; install from the lockfile in an authorized environment to run integration coverage.');
    return;
  }
  const { statusService } = await import('../src/status/service.js');
  const original = statusService.get;
  statusService.get = async () => ({ overall: 'green', lastChecked: new Date().toISOString(), checks: [], history: [] });
  const server = mod.server;
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    statusService.get = original;
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  async function request(url, method = 'GET', token, body) {
    return new Promise((resolve, reject) => {
      const data = body ? JSON.stringify(body) : '';
      const req = http.request({ host: '127.0.0.1', port: server.address().port, path: url, method, headers: {
        ...(token ? { 'x-fastdog-token': token } : {}), 'content-type': 'application/json', 'content-length': Buffer.byteLength(data),
      } }, (res) => {
        let text = '';
        res.on('data', (chunk) => { text += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, text }));
      });
      req.on('error', reject);
      req.end(data);
    });
  }
  const routes = [
    ['GET', '/_fastdog/agents'], ['GET', '/_fastdog/routes'], ['GET', '/_fastdog/metrics'], ['POST', '/_fastdog/routes/reload'],
    ['GET', '/_fastdog/dns/zones'], ['GET', '/_fastdog/dns/zones/app.example.com'],
    ['PUT', '/_fastdog/dns/zones/app.example.com'], ['POST', '/_fastdog/dns/zones/app.example.com/records'],
    ['DELETE', '/_fastdog/dns/zones/app.example.com/records'], ['GET', '/_fastdog/dns/zones/app.example.com/export.bind'],
  ];
  for (const [method, url] of routes) {
    for (const token of [undefined, portal, fake()]) {
      const result = await request(url, method, token);
      assert.equal(result.status, 401, `${method} ${url}`);
      assert.deepEqual(JSON.parse(result.text), { error: 'unauthorized' });
    }
    assert.notEqual((await request(url, method, operator)).status, 401, url);
  }
  assert.equal((await request('/_fastdog/routes/reload', 'POST', undefined, { token: operator })).status, 200);
  for (const url of ['/health', '/status', '/status.json', '/pricing']) assert.equal((await request(url)).status, 200, url);
  const registration = await request('/_fastdog/agents/register', 'POST', operator, { hostname: 'app.example.com', localUpstream: 'http://127.0.0.1:9' });
  assert.equal(registration.status, 201);
  const { default: WebSocket } = await import('ws');
  const id = JSON.parse(registration.text).id;
  const ws = new WebSocket(`ws://127.0.0.1:${server.address().port}/_fastdog/tunnel?agentId=${id}`, { headers: { 'x-fastdog-token': operator } });
  t.after(() => ws.terminate());
  const welcome = await new Promise((resolve, reject) => { ws.once('message', resolve); ws.once('error', reject); });
  assert.equal(JSON.parse(String(welcome)).type, 'welcome');
  ws.close();
  await new Promise((resolve) => ws.once('close', resolve));
  assert.equal((await request('/_fastdog/agents/register', 'POST', portal, { hostname: 'app.example.com', localUpstream: 'http://127.0.0.1:9' })).status, 401);
});
