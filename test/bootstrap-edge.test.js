import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { randomUUID, randomBytes, generateKeyPairSync, sign, createHash, privateDecrypt, constants } from 'node:crypto';
import WebSocket from 'ws';
import { createBootstrap, exchangeTranscript, OAEP_LABEL } from '../src/onboard/bootstrap.js';
import { writeJson, readJson } from '../src/onboard/json.js';
import { issueCredential } from '../src/onboard/credentials.js';
import { proofTranscript, PROOF_HEADER } from '../src/control/agent-proof.js';

const tid = 't_aaaaaaaaaaaaaaaaaaaa', hostname = 'app.example.test', audience = 'https://edge.example.test', origin = 'http://127.0.0.1:8080';
const key = generateKeyPairSync('rsa', { modulusLength: 3072 });
const pss = { key: key.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 };
function proof({ method, target, credentialId, body = Buffer.alloc(0) }) {
  const timestamp = Math.floor(Date.now() / 1000), nonce = randomBytes(32).toString('base64url');
  const signature = sign('sha256', proofTranscript({ method, target, audience, credentialId, timestamp, nonce, body }), pss).toString('base64url');
  return Buffer.from(JSON.stringify({ v: 1, nonce, timestamp, signature })).toString('base64url');
}

test('flag-on edge: legacy agents ignore proofs; candidates register and attach over HTTP/WS only with proofs and are held', { timeout: 20000 }, async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'bootstrap-edge-'));
  const operator = randomBytes(32).toString('hex');
  const active = issueCredential({ tenant_id: tid, hostname }, directory);
  writeJson('tenant_hostnames.json', [{ tenant_id: tid, hostname, status: 'active', txt_value: randomBytes(8).toString('hex'), verified_at: new Date().toISOString(), created_at: new Date().toISOString(), credential_id: active.id }], 0o600, directory);
  Object.assign(process.env, { NODE_ENV: 'test', AGENT_TOKEN: operator, DATA_DIR: directory, INTERNAL_ENABLED: '0', BILLING_ENABLED: 'false', AGENT_BOOTSTRAP_ENABLED: '1', AGENT_BOOTSTRAP_AUDIENCE: audience });
  const service = createBootstrap({ bootstrapEnabled: true, bootstrapAudience: audience, dataDir: directory, issuerCheck: async () => true });
  const { server } = await import('../src/edge/server.js?bootstrap=1');
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const sockets = [];
  t.after(async () => {
    for (const socket of sockets) socket.terminate();
    service.close(); server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); rmSync(directory, { recursive: true, force: true });
    for (const name of ['AGENT_BOOTSTRAP_ENABLED', 'AGENT_BOOTSTRAP_AUDIENCE']) delete process.env[name];
  });
  const base = `127.0.0.1:${server.address().port}`;
  const post = (path, token, body, headers = {}) => fetch(`http://${base}${path}`, { method: 'POST', body, headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, ...headers } });
  const tunnel = (path, token, headers = {}) => new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://${base}${path}`, { headers: { authorization: `Bearer ${token}`, ...headers } });
    const frames = []; sockets.push(ws);
    ws.on('message', (m) => { frames.push(JSON.parse(m)); if (frames.at(-1).type !== 'welcome') resolve({ ws, frames }); });
    ws.once('close', (code) => resolve({ ws, frames, code }));
    ws.once('error', reject);
  });

  // Legacy credential with a junk proof header: accepted on register and upgrade.
  const legacyBody = JSON.stringify({ hostname, localUpstream: origin });
  const legacy = await post('/_fastdog/agents/register', active.token, legacyBody, { [PROOF_HEADER]: 'junk' });
  assert.equal(legacy.status, 201);
  const { id: legacyId } = await legacy.json();
  const ws = new WebSocket(`ws://${base}/_fastdog/tunnel?agentId=${legacyId}`, { headers: { authorization: `Bearer ${active.token}`, [PROOF_HEADER]: 'junk' } });
  sockets.push(ws);
  assert.equal(JSON.parse((await once(ws, 'message'))[0]).type, 'welcome');

  const issued = service.issue(tid, hostname, { origin, deployment_id: randomUUID(), issuance_id: randomUUID(), issuer: { kind: 'session', id: randomUUID(), authorization_generation: 1 } });
  const exchange = { hostname, origin, deployment_id: issued.deployment_id, request_id: randomUUID(), recipient_public_key: key.publicKey.export({ type: 'spki', format: 'pem' }), agent_version: '1.2.3' };
  exchange.proof = sign('sha256', exchangeTranscript(audience, createHash('sha256').update(issued.code).digest('hex'), exchange), pss).toString('base64url');
  const redeemed = await service.exchange(issued.code, exchange, 'ip');
  const token = privateDecrypt({ key: key.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: OAEP_LABEL }, Buffer.from(redeemed.encrypted_token, 'base64url')).toString();
  const credentialId = redeemed.credential_id;

  const target = '/_fastdog/agents/register?candidate=1';
  const body = Buffer.from(JSON.stringify({ hostname, localUpstream: origin }));
  assert.equal((await post(target, token, body)).status, 401);
  assert.equal((await post('/_fastdog/agents/register', token, body, { [PROOF_HEADER]: proof({ method: 'POST', target: '/_fastdog/agents/register', credentialId, body }) })).status, 401);
  // The proof covers the exact body bytes.
  const signed = proof({ method: 'POST', target, credentialId, body });
  assert.equal((await post(target, token, Buffer.from(JSON.stringify({ localUpstream: origin, hostname })), { [PROOF_HEADER]: signed })).status, 401);
  const response = await post(target, token, body, { [PROOF_HEADER]: proof({ method: 'POST', target, credentialId, body }) });
  assert.equal(response.status, 201);
  const reg = await response.json();
  assert.equal(reg.candidate, true);

  const wsTarget = `/_fastdog/tunnel?agentId=${reg.id}&candidate=1`;
  assert.equal((await tunnel(wsTarget, token)).code, 4401);
  const held = await tunnel(wsTarget, token, { [PROOF_HEADER]: proof({ method: 'GET', target: wsTarget, credentialId }) });
  assert.deepEqual(held.frames.map((f) => f.type), ['welcome', 'candidate_status']);
  assert.equal(held.frames[1].state, 'held');
  assert.equal(readJson('agent-credentials.json', [], directory).find((r) => r.id === credentialId).status, 'held');
  // The live legacy agent keeps the host.
  const agents = await (await fetch(`http://${base}/_fastdog/agents`, { headers: { 'x-fastdog-token': operator } })).json();
  assert.deepEqual(agents.agents.map((a) => a.id), [legacyId]);
  assert.equal(ws.readyState, WebSocket.OPEN);
  for (const socket of [ws, held.ws]) { const closed = once(socket, 'close'); socket.close(); await closed; }
});
