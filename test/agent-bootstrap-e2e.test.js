// End to end over loopback: the real agent startAgent against the real edge (server.js, AGENT_BOOTSTRAP_ENABLED=1).
// Exchange is served by the edge's own bootstrapHandler with a test issuer check (production has none configured yet);
// register, candidate WS, the promotion hold, owner confirmation, promotion and active reconnect use server.js.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { randomUUID, randomBytes } from 'node:crypto';
import WebSocket from 'ws';
import { createBootstrap, bootstrapHandler } from '../src/onboard/bootstrap.js';
import { writeJson, readJson } from '../src/onboard/json.js';
import { issueCredential } from '../src/onboard/credentials.js';
import { closeCandidates, confirmCandidate, getAgentByHost } from '../src/control/tunnels.js';
import { startAgent, currentOriginStatus } from '../agent/index.js';
import { readState } from '../agent/state.js';
import { generateKey } from '../agent/protocol.js';
import { issuerCheckFixture } from './helpers/issuer-check.js';

const tid = 't_aaaaaaaaaaaaaaaaaaaa', hostname = 'app.example.test', audience = 'https://edge.example.test';
// The agent's own generator, run before any timed step (state tests cover in-volume generation itself).
const key = generateKey();

// Generous bounds: RSA work in parallel suites can be slow on a loaded runner.
const within = (promise, label, timeoutMs = 20000) => {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), timeoutMs); })])
    .finally(() => clearTimeout(timer));
};
async function until(check, label, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > deadline) assert.fail(`timed out waiting for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
// Tenant traffic for the hostname (fetch cannot set Host).
const viaEdge = (port, target) => new Promise((resolve, reject) => {
  http.get({ host: '127.0.0.1', port, path: target, headers: { host: hostname }, agent: false }, (res) => {
    let body = ''; res.setEncoding('utf8'); res.on('data', (d) => { body += d; }); res.on('end', () => resolve({ status: res.statusCode, body }));
  }).on('error', reject);
});
const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));

test('agent <-> edge: exchange, candidate register, held WS with notice, owner confirmation promotes, active reconnect', { timeout: 120000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-e2e-edge-'));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-e2e-state-'));
  const operator = randomBytes(32).toString('hex');
  const envBefore = JSON.stringify(process.env);

  // The tenant's local app, reached only through the tunnel.
  const app = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(`hello from ${req.url}`); });
  const appPort = await listen(app);
  const origin = `http://127.0.0.1:${appPort}`;

  const active = issueCredential({ tenant_id: tid, hostname }, directory);
  writeJson('tenant_hostnames.json', [{ tenant_id: tid, hostname, status: 'active', txt_value: randomBytes(8).toString('hex'), verified_at: new Date().toISOString(), created_at: new Date().toISOString(), credential_id: active.id }], 0o600, directory);
  // Candidate registration, upgrade and promotion recheck the issuer through the authenticated portal listener.
  const issuers = await issuerCheckFixture(t);
  Object.assign(process.env, { NODE_ENV: 'test', AGENT_TOKEN: operator, DATA_DIR: directory, INTERNAL_ENABLED: '0', BILLING_ENABLED: 'false', AGENT_BOOTSTRAP_ENABLED: '1', AGENT_BOOTSTRAP_AUDIENCE: audience,
    AGENT_BOOTSTRAP_ISSUER_CHECK_URL: issuers.url, AGENT_BOOTSTRAP_ISSUER_CHECK_KEY: issuers.secret });
  const { server } = await import('../src/edge/server.js?agent-e2e=1');
  const edgePort = await listen(server);
  const service = createBootstrap({ bootstrapEnabled: true, bootstrapAudience: audience, dataDir: directory, issuerCheck: async () => true, registry: { closeCandidates, confirmCandidate } });
  let exchanges = 0;
  const handler = bootstrapHandler(service);
  const exchange = http.createServer((req, res) => { exchanges++; handler(req, res); });
  const exchangePort = await listen(exchange);

  const sockets = []; const agents = [];
  t.after(async () => {
    for (const agent of agents) agent.stop?.();
    for (const socket of sockets) socket.terminate();
    service.close();
    for (const s of [server, exchange, app]) { s.closeAllConnections?.(); await new Promise((resolve) => s.close(resolve)); }
    for (const name of ['AGENT_BOOTSTRAP_ENABLED', 'AGENT_BOOTSTRAP_AUDIENCE', 'AGENT_TOKEN', 'DATA_DIR', 'AGENT_BOOTSTRAP_ISSUER_CHECK_URL', 'AGENT_BOOTSTRAP_ISSUER_CHECK_KEY']) delete process.env[name];
    fs.rmSync(directory, { recursive: true, force: true }); fs.rmSync(stateDir, { recursive: true, force: true });
  });

  // The old agent, connected with its legacy credential, keeps serving until promotion.
  const legacy = await fetch(`http://127.0.0.1:${edgePort}/_fastdog/agents/register`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${active.token}` },
    body: JSON.stringify({ hostname, localUpstream: origin }) });
  assert.equal(legacy.status, 201);
  const oldId = (await legacy.json()).id;
  const old = new WebSocket(`ws://127.0.0.1:${edgePort}/_fastdog/tunnel?agentId=${oldId}`, { headers: { authorization: `Bearer ${active.token}` } });
  sockets.push(old);
  assert.equal(JSON.parse((await once(old, 'message'))[0]).type, 'welcome');
  const oldClosed = once(old, 'close');

  const issued = service.issue(tid, hostname, { origin, deployment_id: randomUUID(), issuance_id: randomUUID(), issuer: { kind: 'session', id: randomUUID(), authorization_generation: 1 } });
  const env = { AGENT_BOOTSTRAP: issued.code, AGENT_HOSTNAME: hostname, AGENT_NAME: hostname, AGENT_LOCAL_UPSTREAM: origin, AGENT_DEPLOYMENT_ID: issued.deployment_id,
    EDGE_HTTP_URL: audience, EDGE_WS_URL: 'wss://edge.example.test/_fastdog/tunnel' };
  const fixture = { http: `http://127.0.0.1:${edgePort}`, exchange: `http://127.0.0.1:${exchangePort}`, ws: `ws://127.0.0.1:${edgePort}` };
  const lines = []; const exits = [];
  const capture = (...args) => lines.push(args.join(' '));
  const originals = Object.fromEntries(['log', 'warn', 'error'].map((name) => [name, console[name]]));
  for (const name of Object.keys(originals)) console[name] = capture;
  t.after(() => Object.assign(console, originals));
  const log = { log: capture, warn: capture, error: capture };
  const run = () => startAgent({ env, stateDir, pins: [audience], fixture, log, exit: (code) => exits.push(code), keygen: () => key });

  const first = await within(run(), 'exchange and startup'); agents.push(first);
  assert.equal(first.mode, 'key_bound'); assert.deepEqual(exits, []);
  assert.equal(exchanges, 1);
  const state = readState(stateDir);
  assert.equal(state.status, 'active'); assert.equal(state.promoted, false);
  assert.equal(fs.statSync(path.join(stateDir, 'credential.json')).mode & 0o777, 0o600);

  // Candidate registration and WS readiness: held while the old agent is connected, with the fingerprint notice.
  await until(() => lines.some((l) => l.includes('awaiting owner confirmation or old-agent absence') && l.includes(state.key_fingerprint)), 'held notice');
  assert.equal(readJson('agent-credentials.json', [], directory).find((r) => r.id === state.credential_id).status, 'held');
  assert.equal(getAgentByHost(hostname).id, oldId);
  assert.equal(old.readyState, WebSocket.OPEN);
  assert.equal(currentOriginStatus().bootstrap_status, 'held');
  assert.equal(currentOriginStatus().credential_mode, 'key_bound');

  // Owner confirmation with the fingerprint the agent logged promotes it; the old socket is closed.
  // Promotion awaits the authenticated issuer recheck (candidate register and upgrade already used it).
  const checksBefore = issuers.seen.length;
  assert.ok(checksBefore >= 2);
  assert.deepEqual(await service.confirm(tid, hostname, state.credential_id, { key_fingerprint: state.key_fingerprint }), { promoted: true, credential_id: state.credential_id });
  assert.equal(issuers.seen.length, checksBefore + 1);
  await within(oldClosed, 'old agent socket close');
  await until(() => readState(stateDir).promoted, 'persisted promotion');
  assert.equal(currentOriginStatus().bootstrap_status, 'promoted');
  const proxied = await until(async () => {
    const res = await viaEdge(edgePort, '/through-tunnel');
    return res.status === 200 ? res.body : null;
  }, 'proxied request');
  assert.equal(proxied, 'hello from /through-tunnel');

  // Restart with the same volume and env: persisted credential, active-path register and upgrade, no exchange.
  first.stop();
  await until(() => !getAgentByHost(hostname)?.ws || getAgentByHost(hostname).ws.readyState !== WebSocket.OPEN, 'agent stopped');
  await within(first.loop, 'first agent loop to stop');
  const second = await within(run(), 'restart'); agents.push(second);
  assert.equal(second.mode, 'key_bound');
  assert.equal((await until(async () => { const res = await viaEdge(edgePort, '/again'); return res.status === 200 && res; }, 'reconnected tunnel')).body, 'hello from /again');
  assert.equal(exchanges, 1);
  assert.deepEqual(exits, []);

  // Nothing secret reached logs or the process environment.
  const token = readState(stateDir).token;
  const output = lines.join('\n');
  for (const secret of [token, issued.code, state.private_key.split('\n')[1]]) assert.ok(!output.includes(secret));
  assert.equal(JSON.stringify(process.env).includes(token), false);
  for (const name of ['AGENT_BOOTSTRAP', 'AGENT_DEPLOYMENT_ID']) assert.equal(process.env[name], undefined);
  assert.ok(envBefore.length > 0);
});
