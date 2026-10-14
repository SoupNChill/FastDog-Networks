import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import WebSocket, { WebSocketServer } from 'ws';

const token = 'synthetic-agent-credential';
function launch(extra = {}) {
  const child = spawn(process.execPath, ['agent/index.js'], { env: { ...process.env, FASTDOG_AGENT_NO_MAIN: '0', AGENT_TOKEN: token, AGENT_HOSTNAME: 'app.example.test', ...extra } });
  child.output = '';
  for (const stream of [child.stdout, child.stderr]) stream.on('data', (data) => { child.output += data; });
  return child;
}

test('missing, empty and whitespace tokens refuse startup; NO_MAIN stays importable', () => {
  for (const value of [undefined, '', '   ']) {
    const env = { ...process.env, FASTDOG_AGENT_NO_MAIN: '0' };
    if (value === undefined) delete env.AGENT_TOKEN;
    else env.AGENT_TOKEN = value;
    const result = spawnSync(process.execPath, ['agent/index.js'], { env, encoding: 'utf8', timeout: 3000 });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AGENT_TOKEN is required/);
  }
  const result = spawnSync(process.execPath, ['agent/index.js'], { env: { ...process.env, AGENT_TOKEN: '', FASTDOG_AGENT_NO_MAIN: '1' }, timeout: 3000 });
  assert.equal(result.status, 0);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  test(`agent uses headers only and exits promptly on ${signal}`, { timeout: 5000 }, async (t) => {
    let registration;
    const server = http.createServer(async (req, res) => {
      let body = '';
      for await (const data of req) body += data;
      registration = { headers: req.headers, url: req.url, body: JSON.parse(body) };
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ id: 'synthetic-id' }));
    });
    const wss = new WebSocketServer({ server });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(() => { for (const ws of wss.clients) ws.terminate(); server.closeAllConnections(); server.close(); });
    const base = `127.0.0.1:${server.address().port}`;
    const connected = once(wss, 'connection');
    const child = launch({ EDGE_HTTP_URL: `http://${base}`, EDGE_WS_URL: `ws://${base}/_fastdog/tunnel?token=obsolete` });
    t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
    const [ws, req] = await connected;
    assert.equal(registration.headers.authorization, `Bearer ${token}`);
    assert.equal(registration.headers['x-fastdog-token'], undefined);
    assert.equal(registration.body.token, undefined);
    assert.equal(registration.body.name, '');
    assert.equal(req.headers.authorization, `Bearer ${token}`);
    assert.equal(new URL(req.url, 'http://example.test').searchParams.has('token'), false);
    assert.equal(registration.url.includes(token), false);
    const closed = once(ws, 'close');
    const exited = once(child, 'exit');
    child.kill(signal);
    assert.deepEqual(await exited, [0, null]);
    await closed;
    assert.equal(child.output.includes(token), false);
  });
}

test('agent never logs reflected registration errors or socket close reasons', { timeout: 5000 }, async (t) => {
  let requests = 0;
  const server = http.createServer((_req, res) => {
    res.setHeader('content-type', 'application/json');
    res.statusCode = ++requests === 1 ? 401 : 200;
    res.end(JSON.stringify(requests === 1 ? { error: token } : { id: 'synthetic-id', route: token }));
  });
  const wss = new WebSocketServer({ server });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { for (const ws of wss.clients) ws.terminate(); server.closeAllConnections(); server.close(); });
  const base = `127.0.0.1:${server.address().port}`;
  const connected = once(wss, 'connection');
  const child = launch({ EDGE_HTTP_URL: `http://${base}`, EDGE_WS_URL: `ws://${base}/_fastdog/tunnel` });
  t.after(() => { if (child.exitCode === null) child.kill('SIGKILL'); });
  const [ws] = await connected;
  ws.close(4401, token);
  await once(ws, 'close');
  const exited = once(child, 'exit');
  child.kill('SIGTERM');
  await exited;
  assert.equal(child.output.includes(token), false);
});

test('edge Bearer auth, legacy fallback, header precedence and credential-free logs', { timeout: 10000 }, async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'agent-auth-'));
  Object.assign(process.env, { NODE_ENV: 'test', AGENT_TOKEN: token, DATA_DIR: directory, INTERNAL_ENABLED: '0', BILLING_ENABLED: 'false' });
  const logs = [];
  for (const method of ['log', 'warn', 'error']) t.mock.method(console, method, (...args) => logs.push(args.join(' ')));
  const { server } = await import('../src/edge/server.js');
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); rmSync(directory, { recursive: true, force: true }); });
  const base = `127.0.0.1:${server.address().port}`;
  const register = (authorization, legacy) => fetch(`http://${base}/_fastdog/agents/register`, {
    method: 'POST', headers: { 'content-type': 'application/json', ...(authorization === undefined ? {} : { authorization }) },
    body: JSON.stringify({ hostname: 'app.example.test', localUpstream: 'http://127.0.0.1:9', token: legacy }),
  });
  assert.equal((await register('Bearer wrong', token)).status, 401);
  assert.equal((await register('Basic wrong', token)).status, 401);
  const response = await register(`Bearer ${token}`);
  assert.equal(response.status, 201);
  const { id } = await response.json();
  for (const [header, query, accepted] of [[`Bearer ${token}`, '', true], [undefined, token, true], ['Bearer wrong', token, false], ['Basic wrong', token, false], ['', token, false], [`Bearer ${token}`, 'wrong', true]]) {
    const ws = new WebSocket(`ws://${base}/_fastdog/tunnel?agentId=${id}&token=${query}`, { headers: header === undefined ? {} : { Authorization: header } });
    const outcome = new Promise((resolve, reject) => {
      ws.once('error', reject);
      ws.once('message', () => resolve(true));
      ws.once('close', (code) => { assert.equal(code, 4401); resolve(false); });
    });
    assert.equal(await outcome, accepted);
    if (accepted) { ws.removeAllListeners('close'); const closed = once(ws, 'close'); ws.close(); await closed; }
  }
  assert.equal(logs.join('\n').includes(token), false);
  assert.equal(logs.join('\n').includes('Bearer wrong'), false);
});
