// End to end over loopback with both flags on (test only): the portal issues a code for a session through the real edge
// internal API; the real agent redeems it at the real edge (server.js); every exchange, candidate register/upgrade and
// promotion asks the portal's real issuer-check listener through the authenticated client; the owner confirms the held
// candidate in the portal; traffic flows through the new tunnel; "Revoke agent" in the portal ends it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { writeJson } from '../src/onboard/json.js';
import { issueCredential, validCredential } from '../src/onboard/credentials.js';
import { getAgentByHost } from '../src/control/tunnels.js';
import { startAgent } from '../agent/index.js';
import { readState } from '../agent/state.js';
import { generateKey } from '../agent/protocol.js';
import { fixture, tids } from '../portal/test/helpers.js';
import { createEdgeClient } from '../portal/src/edge-client.js';
import { createIssuerCheckServer, ISSUER_CHECK_PATH } from '../portal/src/issuer-check.js';
import { createIssuerValidator } from '../portal/src/agent-bootstrap.js';

const tid = tids[0], hostname = 'app.example.test', audience = 'https://edge.example.test';
const key = generateKey();
const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
async function until(check, label, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > deadline) assert.fail(`timed out waiting for ${label}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
const viaEdge = (port, target) => new Promise((resolve, reject) => {
  http.get({ host: '127.0.0.1', port, path: target, headers: { host: hostname }, agent: false }, (res) => {
    let body = ''; res.setEncoding('utf8'); res.on('data', (d) => { body += d; }); res.on('end', () => resolve({ status: res.statusCode, body }));
  }).on('error', reject);
});

test('portal -> edge issuance -> agent exchange -> issuer checks -> held -> portal confirmation -> promotion -> revoke', { timeout: 120000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-e2e-edge-'));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'portal-e2e-state-'));
  const portalKey = randomBytes(32).toString('hex'), issuerKey = randomBytes(32).toString('hex'), operator = randomBytes(32).toString('hex');
  t.after(() => { fs.rmSync(directory, { recursive: true, force: true }); fs.rmSync(stateDir, { recursive: true, force: true }); });

  const app = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(`hello from ${req.url}`); });
  const appPort = await listen(app);
  const origin = `http://127.0.0.1:${appPort}`;

  // The edge claim and its current legacy credential (the "old agent" is offline: it never connects in this test).
  const active = issueCredential({ tenant_id: tid, hostname }, directory);
  writeJson('tenant_hostnames.json', [{ tenant_id: tid, hostname, status: 'active', txt_value: randomBytes(8).toString('hex'), verified_at: new Date().toISOString(), created_at: new Date().toISOString(), credential_id: active.id }], 0o600, directory);

  // The portal's issuer-check listener comes first, so the edge can be configured with its address.
  let validate = () => false;
  const issuerCalls = [];
  const issuerServer = createIssuerCheckServer({ secret: issuerKey, validate: (issuer) => { issuerCalls.push(issuer.issuer_kind); return validate(issuer); } });
  const issuerPort = await listen(issuerServer);

  Object.assign(process.env, { NODE_ENV: 'test', AGENT_TOKEN: operator, DATA_DIR: directory, INTERNAL_ENABLED: '1', PORTAL_KEY: portalKey, BILLING_ENABLED: 'false',
    AGENT_BOOTSTRAP_ENABLED: '1', AGENT_BOOTSTRAP_AUDIENCE: audience,
    AGENT_BOOTSTRAP_ISSUER_CHECK_URL: `http://127.0.0.1:${issuerPort}${ISSUER_CHECK_PATH}`, AGENT_BOOTSTRAP_ISSUER_CHECK_KEY: issuerKey });
  const { server, internalServer } = await import('../src/edge/server.js?portal-e2e=1');
  const edgePort = await listen(server);
  const internalPort = await listen(internalServer);

  // Portal with the flag on, wired to the real edge internal API.
  const f = await fixture(t, { edgeUrl: 'https://edge.example-edge.test', agentBootstrap: true }, { edge: createEdgeClient({ baseUrl: `http://127.0.0.1:${internalPort}`, portalKey }) });
  f.advance(Date.now() - f.now());
  validate = createIssuerValidator({ store: f.store, now: f.now });
  const a = await f.seed();

  const agents = [];
  const lines = []; const exits = [];
  const capture = (...args) => lines.push(args.join(' '));
  const originals = Object.fromEntries(['log', 'warn', 'error'].map((name) => [name, console[name]]));
  for (const name of Object.keys(originals)) console[name] = capture;
  t.after(async () => {
    Object.assign(console, originals);
    for (const agent of agents) agent.stop?.();
    for (const s of [server, internalServer, issuerServer, app]) { s.closeAllConnections?.(); await new Promise((resolve) => s.close(resolve)); }
    for (const name of ['AGENT_BOOTSTRAP_ENABLED', 'AGENT_BOOTSTRAP_AUDIENCE', 'AGENT_BOOTSTRAP_ISSUER_CHECK_URL', 'AGENT_BOOTSTRAP_ISSUER_CHECK_KEY', 'AGENT_TOKEN', 'DATA_DIR', 'INTERNAL_ENABLED', 'PORTAL_KEY']) delete process.env[name];
  });

  // 1. Portal issuance (session, CSRF, exact Origin) through the edge's internal POST /bootstraps.
  const issued = await a.client.call(`/api/hostnames/${hostname}/bootstraps`, 'POST', { origin });
  assert.equal(issued.status, 201, JSON.stringify(issued.data));
  const code = issued.data.code;
  assert.match(code, /^fdab_/);

  // 2. The agent redeems it at the edge (canonical exchange route on the pinned authority) and registers as a candidate.
  const env = { AGENT_BOOTSTRAP: code, AGENT_HOSTNAME: hostname, AGENT_NAME: hostname, AGENT_LOCAL_UPSTREAM: origin, AGENT_DEPLOYMENT_ID: issued.data.deployment_id,
    EDGE_HTTP_URL: audience, EDGE_WS_URL: 'wss://edge.example.test/_fastdog/tunnel' };
  const fixtureUrls = { http: `http://127.0.0.1:${edgePort}`, ws: `ws://127.0.0.1:${edgePort}` };
  const log = { log: capture, warn: capture, error: capture };
  const agent = await startAgent({ env, stateDir, pins: [audience], fixture: fixtureUrls, log, exit: (c) => exits.push(c), keygen: () => key });
  agents.push(agent);
  assert.equal(agent.mode, 'key_bound'); assert.deepEqual(exits, []);
  const state = readState(stateDir);
  assert.equal(state.status, 'active');

  // 3. Held: the active credential exists and the edge started less than absent_for ago. Exchange, register and upgrade
  //    each passed an authenticated session issuer check.
  await until(() => lines.some((l) => l.includes('awaiting owner confirmation') && l.includes(state.key_fingerprint)), 'held notice');
  assert.deepEqual(issuerCalls, ['session', 'session', 'session']);
  assert.equal(getAgentByHost(hostname), null);

  // 4. Owner confirmation in the portal (session + CSRF) promotes after one more issuer check.
  const confirm = await a.client.call(`/api/hostnames/${hostname}/bootstraps/candidates/${state.credential_id}/confirm`, 'POST', { key_fingerprint: state.key_fingerprint });
  assert.deepEqual([confirm.status, confirm.data], [200, { promoted: true, credential_id: state.credential_id }]);
  assert.equal(issuerCalls.length, 4);
  await until(() => readState(stateDir).promoted, 'persisted promotion');
  assert.equal(validCredential(active.token, hostname, directory), false, 'the replaced credential is revoked');
  const proxied = await until(async () => { const res = await viaEdge(edgePort, '/through-tunnel'); return res.status === 200 ? res.body : null; }, 'proxied request');
  assert.equal(proxied, 'hello from /through-tunnel');
  assert.equal((await a.client.call(`/api/hostnames/${hostname}/bootstraps`)).data.bootstraps[0].status, 'used');

  // 5. Revoke agent in the portal: the tunnel closes and nothing replaces it.
  const ws = getAgentByHost(hostname).ws;
  const closed = once(ws, 'close');
  const revoked = await a.client.call(`/api/hostnames/${hostname}/revoke-agent`, 'POST', { confirm: true });
  assert.deepEqual(revoked.data, { hostname, revoked: true });
  await closed;
  assert.notEqual((await viaEdge(edgePort, '/after-revoke')).body, 'hello from /after-revoke');
  agent.stop();

  // No code, token, key or service secret in logs or portal state.
  const output = lines.join('\n');
  for (const secret of [code, state.token, state.private_key.split('\n')[1], issuerKey, portalKey]) assert.ok(!output.includes(secret));
  for (const file of fs.readdirSync(f.dataDir)) {
    const p = path.join(f.dataDir, file);
    if (fs.statSync(p).isFile()) assert.ok(!fs.readFileSync(p, 'utf8').includes(code), file);
  }
});
