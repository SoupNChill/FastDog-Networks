import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID, randomBytes, generateKeyPairSync, sign, createHash, privateDecrypt, constants } from 'node:crypto';
import { PassThrough } from 'node:stream';
import { EventEmitter } from 'node:events';
import { createBootstrap, exchangeTranscript, OAEP_LABEL } from '../src/onboard/bootstrap.js';
import { readJson, writeJson, AUTH_LOCK } from '../src/onboard/json.js';
import { issueCredential, validCredential } from '../src/onboard/credentials.js';
import { createInternalServer } from '../src/internal/server.js';
import { validCandidateCredential } from '../src/onboard/candidates.js';
import { proofTranscript, agentAuthContext, agentNonces, createNonceCache, parseProof, PROOF_HEADER } from '../src/control/agent-proof.js';
import { registerAgent, attachWs, detachWs, closeHost, getAgentByHost, listAgents, configureCandidates, candidateReady, sweepCandidates,
  closeCandidates, confirmCandidate, absentForSetting, _resetForTests } from '../src/control/tunnels.js';

const tid = 't_aaaaaaaaaaaaaaaaaaaa', other = 't_bbbbbbbbbbbbbbbbbbbb';
const hostname = 'app.example.test', otherHost = 'other.example.test', audience = 'https://edge.example.test';
const origin = 'http://127.0.0.1:8080';
const fakeSecret = () => randomBytes(32).toString('hex');
const keys = [0, 1].map(() => generateKeyPairSync('rsa', { modulusLength: 3072 }));
const fingerprint = (key) => createHash('sha256').update(key.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
const registry = { getAgentByHost, closeHost, closeCandidates, confirmCandidate };
const REGISTER = '/_fastdog/agents/register?candidate=1';

function socket() {
  return { readyState: 1, sent: [], closed: null, send(m) { this.sent.push(JSON.parse(m)); },
    close(code) { this.readyState = 3; this.closed = code ?? true; }, terminate() { this.readyState = 3; this.closed = 'terminated'; } };
}

function fixture(t, extra = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bootstrap-candidates-'));
  let time = Date.now();
  t.after(() => { _resetForTests(); fs.rmSync(directory, { recursive: true, force: true }); });
  const active = issueCredential({ tenant_id: tid, hostname }, directory, () => time);
  const second = issueCredential({ tenant_id: other, hostname: otherHost }, directory, () => time);
  const claim = (tenant, host, credential) => ({ tenant_id: tenant, hostname: host, status: 'active', txt_value: fakeSecret(),
    verified_at: new Date(time).toISOString(), created_at: new Date(time).toISOString(), credential_id: credential.id });
  writeJson('tenant_hostnames.json', [claim(tid, hostname, active), claim(other, otherHost, second)], 0o600, directory);
  const now = () => time;
  const options = { bootstrapEnabled: true, bootstrapAudience: audience, dataDir: directory, now, issuerCheck: async () => true, registry, ...extra };
  const service = createBootstrap(options);
  t.after(() => service.close());
  // A synchronous issuer check keeps these registry calls synchronous; test/issuer-check.test.js covers the real client.
  configureCandidates({ now, absentForMs: 300000, issuerCheck: extra.registryIssuerCheck ?? (() => true) });

  async function redeem(key = keys[0]) {
    const issued = service.issue(tid, hostname, { origin, deployment_id: randomUUID(), issuance_id: randomUUID(), issuer: { kind: 'session', id: randomUUID(), authorization_generation: 1 } });
    const body = { hostname, origin, deployment_id: issued.deployment_id, request_id: randomUUID(), recipient_public_key: key.publicKey.export({ type: 'spki', format: 'pem' }), agent_version: '1.2.3' };
    body.proof = sign('sha256', exchangeTranscript(audience, createHash('sha256').update(issued.code).digest('hex'), body), { key: key.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64url');
    const result = await service.exchange(issued.code, body, 'ip');
    const token = privateDecrypt({ key: key.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: OAEP_LABEL }, Buffer.from(result.encrypted_token, 'base64url')).toString();
    return { token, id: result.credential_id, key, issued, body };
  }
  function header(key, { method, target, credentialId, body = Buffer.alloc(0), timestamp = Math.floor(time / 1000), nonce = randomBytes(32).toString('base64url') }) {
    const signature = sign('sha256', proofTranscript({ method, target, audience, credentialId, timestamp, nonce, body }), { key: key.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64url');
    return Buffer.from(JSON.stringify({ v: 1, nonce, timestamp, signature })).toString('base64url');
  }
  const context = (values, method, target, body = Buffer.alloc(0)) => ({ values, method, target, audience, body });
  function registerProof(c, overrides = {}) {
    const body = Buffer.from(JSON.stringify({ hostname, localUpstream: origin }));
    return context([header(c.key, { method: 'POST', target: REGISTER, credentialId: c.id, body, ...overrides })], 'POST', REGISTER, body);
  }
  const register = (c, proof = registerProof(c), host = hostname) => registerAgent({ hostname: host, localUpstream: origin, token: c.token, candidate: true, dataDir: directory, proof });
  function wsProof(c, agentId, overrides = {}) {
    const target = `/_fastdog/tunnel?agentId=${agentId}&candidate=1`;
    return context([header(c.key, { method: 'GET', target, credentialId: c.id, ...overrides })], 'GET', target);
  }
  // Register, attach and mark ready (welcome sent), as the edge WS handler does.
  function connect(c) {
    const reg = register(c); const ws = socket();
    assert.equal(attachWs(reg.id, ws, c.token, { candidate: true, proof: wsProof(c, reg.id) }), true);
    return { reg, ws, state: candidateReady(reg.id, ws) };
  }
  function connectActive() {
    const reg = registerAgent({ hostname, localUpstream: origin, token: active.token, expectedToken: fakeSecret(), dataDir: directory });
    const ws = socket(); assert.equal(attachWs(reg.id, ws, active.token), true);
    return { reg, ws };
  }
  const record = (id) => readJson('agent-credentials.json', [], directory).find((r) => r.id === id);
  const owner = () => readJson('tenant_hostnames.json', [], directory).find((c) => c.hostname === hostname);
  return { directory, active, second, options, service, redeem, header, context, registerProof, register, wsProof, connect, connectActive, record, owner,
    now, advance: (ms) => { time += ms; } };
}

function invoke(handler, { method = 'POST', url, body = {}, headers = {} }) {
  const req = new PassThrough(); Object.assign(req, { method, url, headers, socket: { remoteAddress: '127.0.0.1' } });
  const res = new EventEmitter(); res.writableEnded = false;
  return new Promise((resolve, reject) => {
    res.writeHead = (status) => { res.statusCode = status; };
    res.end = (raw = '') => { res.writableEnded = true; res.writableFinished = true; res.emit('finish'); resolve({ status: res.statusCode, body: raw ? JSON.parse(raw) : null }); };
    Promise.resolve(handler(req, res)).catch(reject);
    req.end(JSON.stringify(body));
  });
}

test('legacy credentials ignore the proof header with the flag off and on; disabled context is empty', (t) => {
  for (const enabled of [false, true]) {
    const f = fixture(t);
    if (!enabled) _resetForTests();
    const garbage = f.context(['not-a-proof', 'x'], 'POST', REGISTER);
    const before = agentNonces.size;
    const reg = registerAgent({ hostname, localUpstream: origin, token: f.active.token, expectedToken: fakeSecret(), dataDir: f.directory, proof: garbage });
    assert.equal(attachWs(reg.id, socket(), f.active.token, { proof: garbage }), true);
    assert.equal(validCredential(f.active.token, hostname, f.directory, f.now, garbage), true);
    assert.equal(agentNonces.size, before);
    _resetForTests();
  }
  const req = { method: 'POST', url: REGISTER, rawHeaders: [PROOF_HEADER, 'a', 'X-Fastdog-Agent-Proof', 'b'] };
  assert.deepEqual(agentAuthContext(req, { enabled: false, audience }), {});
  const on = agentAuthContext(req, { enabled: true, audience });
  assert.equal(on.candidate, true); assert.deepEqual(on.proof.values, ['a', 'b']); assert.equal(on.proof.target, REGISTER);
  assert.equal(agentAuthContext({ ...req, url: '/_fastdog/agents/register' }, { enabled: true, audience }).candidate, false);
});

test('key-bound credentials need a valid proof; missing, wrong-key, replayed, skewed and tampered proofs get 401', async (t) => {
  const f = fixture(t); const c = await f.redeem();
  f.advance(1000 - (f.now() % 1000));
  const stored = f.record(c.id);
  assert.equal(stored.key_fingerprint, fingerprint(keys[0])); assert.equal(typeof stored.public_key, 'string');
  const unauthorized = { status: 401, message: 'unauthorized' };
  assert.throws(() => f.register(c, null), unauthorized);
  assert.throws(() => f.register(c, f.context([], 'POST', REGISTER)), unauthorized);
  assert.throws(() => f.register({ ...c, key: keys[1] }), unauthorized);
  const tampered = f.registerProof(c); tampered.body = Buffer.from(JSON.stringify({ hostname, localUpstream: 'http://127.0.0.1:9090' }));
  assert.throws(() => f.register(c, tampered), unauthorized);
  const proof = f.registerProof(c);
  assert.throws(() => f.register(c, { ...proof, values: [proof.values[0], proof.values[0]] }), unauthorized);
  const decoded = JSON.parse(Buffer.from(proof.values[0], 'base64url'));
  for (const variant of [{ ...decoded, extra: 1 }, { signature: decoded.signature, v: 1, nonce: decoded.nonce, timestamp: decoded.timestamp }]) {
    assert.equal(parseProof([Buffer.from(JSON.stringify(variant)).toString('base64url')]), null);
  }
  assert.equal(parseProof([Buffer.from(` ${JSON.stringify(decoded)}`).toString('base64url')]), null);
  const reg = f.register(c, proof);
  assert.equal(reg.candidate, true);
  // Replay on the same path and across register/upgrade.
  assert.throws(() => f.register(c, proof), unauthorized);
  assert.equal(attachWs(reg.id, socket(), c.token, { candidate: true, proof: f.wsProof(c, reg.id, { nonce: decoded.nonce }) }), false);
  // Clock window: 60 s either way inclusive.
  const seconds = Math.floor(f.now() / 1000);
  for (const skew of [-61, 61]) assert.equal(attachWs(reg.id, socket(), c.token, { candidate: true, proof: f.wsProof(c, reg.id, { timestamp: seconds + skew }) }), false);
  // The signed target binds agentId and the candidate selector.
  const wrongTarget = f.wsProof(c, reg.id); wrongTarget.target = `/_fastdog/tunnel?agentId=${reg.id}`;
  assert.equal(attachWs(reg.id, socket(), c.token, { candidate: true, proof: wrongTarget }), false);
  assert.equal(attachWs(reg.id, socket(), c.token, { candidate: true }), false);
  assert.equal(attachWs(reg.id, socket(), c.token, { candidate: true, proof: f.wsProof(c, reg.id, { timestamp: seconds - 60 }) }), true);
});

test('pending credentials with valid proofs never authenticate on the active path or touch the active registry', async (t) => {
  const f = fixture(t); const a = f.connectActive(); const c = await f.redeem();
  const activeProof = () => { const body = Buffer.from('{}'); return f.context([f.header(c.key, { method: 'POST', target: '/_fastdog/agents/register', credentialId: c.id, body })], 'POST', '/_fastdog/agents/register', body); };
  assert.throws(() => registerAgent({ hostname, localUpstream: origin, token: c.token, expectedToken: fakeSecret(), dataDir: f.directory, proof: activeProof() }), { status: 401 });
  assert.equal(validCredential(c.token, hostname, f.directory, f.now, activeProof()), false);
  assert.equal(getAgentByHost(hostname).id, a.reg.id); assert.equal(a.ws.closed, null); assert.equal(listAgents().length, 1);
});

test('a ready candidate is held while the active agent is connected and promotes after 300 s of continuous absence', async (t) => {
  const f = fixture(t); const a = f.connectActive(); const c = await f.redeem();
  const cand = f.connect(c);
  assert.equal(cand.state, 'held');
  assert.equal(f.record(c.id).status, 'held');
  assert.equal(getAgentByHost(hostname).id, a.reg.id); assert.equal(a.ws.closed, null);
  assert.deepEqual(listAgents().map((x) => x.id), [a.reg.id]);
  assert.deepEqual(cand.ws.sent.at(-1), { type: 'candidate_status', state: 'held' });

  detachWs(a.reg.id, a.ws);
  f.advance(299000); sweepCandidates();
  assert.equal(f.record(c.id).status, 'held');
  // Reattachment of the active agent resets the absence clock.
  const again = socket(); assert.equal(attachWs(a.reg.id, again, f.active.token), true);
  f.advance(10000); sweepCandidates(); assert.equal(f.record(c.id).status, 'held');
  detachWs(a.reg.id, again);
  f.advance(299999); sweepCandidates(); assert.equal(f.record(c.id).status, 'held');
  f.advance(1); sweepCandidates();

  assert.equal(f.record(c.id).status, 'active');
  assert.equal(getAgentByHost(hostname).id, cand.reg.id);
  assert.equal(getAgentByHost(hostname).ws, cand.ws);
  assert.deepEqual(cand.ws.sent.at(-1), { type: 'candidate_status', state: 'promoted' });
  // The replaced credential is revoked in the same transaction that selected the candidate.
  assert.equal(f.owner().credential_id, c.id);
  assert.ok(f.record(f.active.id).revoked_at);
  assert.equal(f.record(f.active.id).revoked_at, f.record(c.id).promoted_at);
  assert.equal(validCredential(f.active.token, hostname, f.directory, f.now), false);
  assert.throws(() => registerAgent({ hostname, localUpstream: origin, token: f.active.token, expectedToken: fakeSecret(), dataDir: f.directory }), { status: 401 });
  // The promoted key-bound credential now uses the active path, with a proof only.
  const body = Buffer.from('{}'); const target = '/_fastdog/agents/register';
  assert.throws(() => registerAgent({ hostname, localUpstream: origin, token: c.token, expectedToken: fakeSecret(), dataDir: f.directory }), { status: 401 });
  const reg = registerAgent({ hostname, localUpstream: origin, token: c.token, expectedToken: fakeSecret(), dataDir: f.directory,
    proof: f.context([f.header(c.key, { method: 'POST', target, credentialId: c.id, body })], 'POST', target, body) });
  const upgrade = `/_fastdog/tunnel?agentId=${reg.id}`;
  assert.equal(attachWs(reg.id, socket(), c.token), false);
  assert.equal(attachWs(reg.id, socket(), c.token, { proof: f.context([f.header(c.key, { method: 'GET', target: upgrade, credentialId: c.id })], 'GET', upgrade) }), true);
});

test('edge restart does not count as absence; with nothing connected promotion waits for absent_for since start', async (t) => {
  const f = fixture(t); const c = await f.redeem();
  f.advance(10000);
  const cand = f.connect(c);
  assert.equal(cand.state, 'held');
  f.advance(289999); sweepCandidates(); assert.equal(f.record(c.id).status, 'held');
  f.advance(1); sweepCandidates();
  assert.equal(f.record(c.id).status, 'active'); assert.equal(getAgentByHost(hostname).id, cand.reg.id);

  _resetForTests();
  const g = fixture(t); g.advance(300000); const d = await g.redeem();
  assert.equal(g.connect(d).state, 'promoted');
});

test('a held candidate never displaces a live agent and expires at hold_until; unready candidates expire at activate_by', async (t) => {
  const f = fixture(t); const a = f.connectActive(); const c = await f.redeem();
  const cand = f.connect(c); assert.equal(cand.state, 'held');
  for (let i = 0; i < 12; i++) { f.advance(299000); sweepCandidates(); }
  f.advance(3599999 - 12 * 299000); sweepCandidates();
  assert.equal(f.record(c.id).status, 'held'); assert.equal(a.ws.closed, null);
  // A disconnected held candidate may reattach until hold_until.
  detachWs(cand.reg.id, cand.ws); sweepCandidates();
  const back = f.connect(c); assert.equal(back.state, 'held');
  f.advance(1); sweepCandidates();
  assert.ok(f.record(c.id).revoked_at); assert.equal(back.ws.closed, 4401);
  assert.equal(getAgentByHost(hostname).id, a.reg.id); assert.equal(a.ws.closed, null);
  assert.equal(validCredential(f.active.token, hostname, f.directory, f.now), true);

  _resetForTests();
  const g = fixture(t); const d = await g.redeem();
  const reg = g.register(d);
  g.advance(119999); sweepCandidates(); assert.equal(g.record(d.id).revoked_at, null);
  g.advance(1); sweepCandidates();
  assert.ok(g.record(d.id).revoked_at);
  assert.equal(attachWs(reg.id, socket(), d.token, { candidate: true, proof: g.wsProof(d, reg.id) }), false);
  assert.throws(() => g.register(d), { status: 401 });
});

test('owner confirmation promotes a held candidate; mismatch is 409 and other tenants get the same 404', async (t) => {
  const f = fixture(t); const a = f.connectActive(); const c = await f.redeem();
  const portalKey = fakeSecret();
  const handle = createInternalServer({ ...f.options, portalKey, agentToken: fakeSecret() }).listeners('request')[0];
  const headers = { 'x-fastdog-portal-key': portalKey };
  const confirm = (tenant, host, id, key_fingerprint = fingerprint(keys[0]), extra = {}) =>
    invoke(handle, { url: `/internal/v1/tenants/${tenant}/hostnames/${host}/bootstraps/candidates/${id}/confirm`, headers, body: { key_fingerprint }, ...extra });
  // Not yet held (no tunnel) is a mismatch, not a lookup miss.
  assert.equal((await confirm(tid, hostname, c.id)).status, 409);
  const cand = f.connect(c); assert.equal(cand.state, 'held');
  assert.equal((await confirm(tid, hostname, c.id, undefined, { headers: {} })).status, 401);
  assert.equal((await confirm(tid, hostname, c.id, undefined, { method: 'GET' })).status, 405);
  const crossHost = await confirm(other, hostname, c.id); const unknownHost = await confirm(tid, 'missing.example.test', c.id);
  assert.deepEqual([crossHost.status, crossHost.body], [404, { error: 'hostname_not_found' }]);
  assert.deepEqual(unknownHost, crossHost);
  const crossId = await confirm(other, otherHost, c.id); const unknownId = await confirm(tid, hostname, randomUUID());
  assert.deepEqual([crossId.status, crossId.body], [404, { error: 'candidate_not_found' }]);
  assert.deepEqual(unknownId, crossId);
  assert.deepEqual((await confirm(tid, hostname, c.id, fingerprint(keys[1]))).body, { error: 'candidate_mismatch' });
  assert.equal(f.record(c.id).status, 'held'); assert.equal(a.ws.closed, null);
  // A candidate token presented for another tenant's hostname gets the same 401 as a bad token.
  assert.throws(() => f.register(c, f.registerProof(c), otherHost), { status: 401, message: 'unauthorized' });
  assert.throws(() => registerAgent({ hostname, localUpstream: origin, token: fakeSecret(), candidate: true, dataDir: f.directory, proof: f.registerProof(c) }), { status: 401, message: 'unauthorized' });

  const ok = await confirm(tid, hostname, c.id);
  assert.deepEqual([ok.status, ok.body], [200, { promoted: true, credential_id: c.id }]);
  assert.equal(a.ws.closed, 'terminated'); assert.equal(getAgentByHost(hostname).id, cand.reg.id);
  assert.ok(f.record(f.active.id).revoked_at); assert.equal(f.owner().credential_id, c.id);
  assert.equal((await confirm(tid, hostname, c.id)).status, 409);
  const offHandle = createInternalServer({ ...f.options, bootstrapEnabled: false, portalKey, agentToken: fakeSecret() }).listeners('request')[0];
  assert.equal((await invoke(offHandle, { url: `/internal/v1/tenants/${tid}/hostnames/${hostname}/bootstraps/candidates/${c.id}/confirm`, headers, body: {} })).status, 404);
});

test('reissue and cancel revoke unpromoted candidates and close them without touching the active agent', async (t) => {
  const f = fixture(t); const a = f.connectActive();
  const c = await f.redeem(); const held = f.connect(c); assert.equal(held.state, 'held');
  const d = await f.redeem(keys[1]);
  assert.ok(f.record(c.id).revoked_at); assert.equal(held.ws.closed, 4401);
  assert.throws(() => f.register(c), { status: 401 });
  // The consumed code keeps its used diagnostic for different-key reuse.
  const reuse = { ...c.body, request_id: randomUUID(), recipient_public_key: keys[1].publicKey.export({ type: 'spki', format: 'pem' }) };
  reuse.proof = sign('sha256', exchangeTranscript(audience, createHash('sha256').update(c.issued.code).digest('hex'), reuse), { key: keys[1].privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64url');
  await assert.rejects(() => f.service.exchange(c.issued.code, reuse, 'ip'), { status: 409 });
  const pending = f.register(d);
  f.service.cancel(tid, hostname);
  assert.ok(f.record(d.id).revoked_at);
  assert.equal(attachWs(pending.id, socket(), d.token, { candidate: true, proof: f.wsProof(d, pending.id) }), false);
  assert.equal(getAgentByHost(hostname).id, a.reg.id); assert.equal(a.ws.closed, null);
  assert.equal(validCredential(f.active.token, hostname, f.directory, f.now), true);
});

test('revocation paths remove candidates; candidate disconnect never closes the active host', async (t) => {
  const f = fixture(t); const a = f.connectActive(); const c = await f.redeem();
  const cand = f.connect(c);
  detachWs(cand.reg.id, cand.ws);
  assert.equal(getAgentByHost(hostname).id, a.reg.id); assert.equal(a.ws.closed, null);
  const again = f.connect(c);
  closeHost(hostname);
  assert.equal(again.ws.closed, 4401); assert.equal(getAgentByHost(hostname), null);
  assert.equal(attachWs(again.reg.id, socket(), c.token, { candidate: true, proof: f.wsProof(c, again.reg.id) }), false);
});

test('nonce cache enforces per-credential and global caps, fails closed and frees entries after expiry', () => {
  const cache = createNonceCache({ perCredential: 2, global: 3 });
  assert.equal(cache.consume('a', 'n1', 100, 0), true);
  assert.equal(cache.consume('a', 'n1', 100, 0), false);
  assert.equal(cache.consume('a', 'n2', 100, 0), true);
  assert.equal(cache.consume('a', 'n3', 100, 0), false);
  assert.equal(cache.consume('b', 'n1', 100, 0), true);
  assert.equal(cache.consume('c', 'n1', 100, 0), false);
  assert.equal(cache.size, 3);
  // Full sweeps at capacity run at most once per second.
  assert.equal(cache.consume('c', 'n1', 5000, 500), false);
  assert.equal(cache.consume('c', 'n1', 5000, 1000), true);
  assert.equal(cache.consume('a', 'n1', 5000, 1000), true);
});

test('absent_for setting defaults to 300 s and accepts only 60-3600', () => {
  assert.equal(absentForSetting(undefined), 300000);
  assert.equal(absentForSetting('60'), 60000); assert.equal(absentForSetting('3600'), 3600000);
  for (const value of ['59', '3601', '1.5', 'x']) assert.throws(() => absentForSetting(value));
});

test('the bound public key is immutable like the fingerprint', async (t) => {
  const f = fixture(t); const c = await f.redeem();
  const records = readJson('agent-credentials.json', [], f.directory);
  records.find((r) => r.id === c.id).public_key = keys[1].publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  assert.throws(() => writeJson('agent-credentials.json', records, 0o600, f.directory), /immutable_key_binding/);
});

test('proof failures and candidate flows never log tokens, proofs or keys', async (t) => {
  const f = fixture(t); const c = await f.redeem(); const logs = [];
  const originals = Object.fromEntries(['log', 'warn', 'error', 'info'].map((name) => [name, console[name]]));
  try {
    for (const name of Object.keys(originals)) console[name] = (...args) => logs.push(args);
    const proof = f.registerProof(c);
    assert.throws(() => f.register({ ...c, key: keys[1] }));
    const reg = f.register(c, proof); assert.throws(() => f.register(c, proof));
    const ws = socket(); attachWs(reg.id, ws, c.token, { candidate: true, proof: f.wsProof(c, reg.id) }); candidateReady(reg.id, ws);
    const captured = JSON.stringify({ logs, sent: ws.sent });
    for (const secret of [c.token, proof.values[0], f.record(c.id).public_key]) assert.ok(!captured.includes(secret));
  } finally { Object.assign(console, originals); }
});

test('M2 review LOW: an active re-registration with its socket already down restarts the absence clock', async (t) => {
  const f = fixture(t); const a = f.connectActive(); const c = await f.redeem();
  const cand = f.connect(c);
  assert.equal(cand.state, 'held');
  detachWs(a.reg.id, a.ws);
  f.advance(299000);
  // The active agent registers again but has not attached its WS yet; that gap is not continuous absence.
  const again = registerAgent({ hostname, localUpstream: origin, token: f.active.token, expectedToken: fakeSecret(), dataDir: f.directory });
  f.advance(2000); sweepCandidates();
  assert.equal(f.record(c.id).status, 'held');
  assert.equal(getAgentByHost(hostname).id, again.id);
  f.advance(297000); sweepCandidates(); assert.equal(f.record(c.id).status, 'held');
  f.advance(1000); sweepCandidates();
  assert.equal(f.record(c.id).status, 'active');
});

test('M2 review LOW: an unknown candidate token is rejected before the writer lock or any expiry write', async (t) => {
  const f = fixture(t); const c = await f.redeem();
  f.advance(121000);
  const unknown = randomBytes(32).toString('hex');
  // A competing live writer holds the lock: the unauthenticated lookup must not wait on it or fail with 503.
  const lock = path.join(f.directory, AUTH_LOCK);
  fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, nonce: randomUUID(), created: Date.now() }), { mode: 0o600 });
  assert.equal(validCandidateCredential(unknown, hostname, f.directory, f.now, undefined), null);
  assert.throws(() => registerAgent({ hostname, localUpstream: origin, token: unknown, candidate: true, dataDir: f.directory }), { status: 401 });
  fs.unlinkSync(lock);
  // No deadline revocation was written on that path; an authenticated bootstrap operation still expires it.
  assert.ok(!f.record(c.id).revoked_at);
  assert.equal(validCandidateCredential(c.token, hostname, f.directory, f.now, undefined), null);
  f.service.status(tid, hostname, c.issued.issuance_id);
  assert.ok(f.record(c.id).revoked_at);
});

// Milestone 4: issuer eligibility at candidate registration, upgrade, promotion and owner confirmation.
test('candidate register and upgrade recheck the issuer: ineligible is 401, unavailable is 503, neither touches the registry', async (t) => {
  let verdict = true; const seen = [];
  const f = fixture(t, { registryIssuerCheck: (issuer) => { seen.push(issuer); if (verdict === 'throw') throw new Error('portal down'); return verdict; } });
  const a = f.connectActive(); const c = await f.redeem();
  // The candidate record carries only the issuer's kind, ID and generation, copied from the code at exchange.
  assert.deepEqual(Object.keys(f.record(c.id).issuer).sort(), ['authorization_generation', 'id', 'kind']);
  assert.equal(seen.length, 0);
  verdict = false; assert.throws(() => f.register(c), { status: 401, message: 'unauthorized' });
  verdict = 'throw'; assert.throws(() => f.register(c), { status: 503, message: 'bootstrap_unavailable' });
  verdict = 'yes'; assert.throws(() => f.register(c), { status: 503 });
  assert.deepEqual(listAgents().map((x) => x.id), [a.reg.id]); assert.equal(a.ws.closed, null);
  assert.equal(seen.at(-1).kind, 'session');
  verdict = true; const reg = f.register(c);
  for (const [value, expected] of [[false, false], ['throw', false], [true, true]]) {
    verdict = value;
    assert.equal(attachWs(reg.id, socket(), c.token, { candidate: true, proof: f.wsProof(c, reg.id) }), expected, String(value));
  }
  // Without any configured checker every candidate path fails closed.
  configureCandidates({ now: f.now, absentForMs: 300000 });
  assert.throws(() => f.register(c), { status: 503 });
});

test('promotion rechecks the issuer: unavailable leaves the candidate held until its deadline; ineligible drops it; the active agent stays', async (t) => {
  let verdict = true;
  const f = fixture(t, { registryIssuerCheck: () => { if (verdict === 'throw') throw new Error('portal down'); return verdict; } });
  const a = f.connectActive(); const c = await f.redeem();
  const cand = f.connect(c); assert.equal(cand.state, 'held');
  detachWs(a.reg.id, a.ws);
  // Holding needs no issuer check; a promotable candidate does.
  verdict = 'throw'; f.advance(300000); sweepCandidates();
  assert.equal(f.record(c.id).status, 'held'); assert.equal(getAgentByHost(hostname).id, a.reg.id); assert.equal(f.owner().credential_id, f.active.id);
  assert.equal(cand.ws.closed, null);
  // Owner confirmation while the check is unavailable: 503, nothing changes.
  await assert.rejects(Promise.resolve().then(() => f.service.confirm(tid, hostname, c.id, { key_fingerprint: fingerprint(keys[0]) })), { status: 503 });
  assert.equal(f.record(c.id).status, 'held');
  verdict = false; sweepCandidates();
  assert.equal(cand.ws.closed, 4401); assert.equal(f.owner().credential_id, f.active.id);
  assert.equal(validCredential(f.active.token, hostname, f.directory, f.now), true);
  assert.notEqual(f.record(c.id).status, 'active');
});

test('an asynchronous issuer check makes candidate paths asynchronous and is awaited before any registry change', async (t) => {
  let release; let verdict = true;
  const f = fixture(t, { registryIssuerCheck: () => new Promise((resolve) => { release = () => resolve(verdict); }) });
  // Edge started 300 s ago and no active agent is connected, so a ready candidate is promotable.
  f.advance(300000);
  const c = await f.redeem();
  const pending = f.register(c);
  assert.equal(typeof pending.then, 'function'); assert.equal(listAgents().length, 0);
  release(); const reg = await pending; assert.equal(reg.candidate, true);
  const ws = socket();
  const attaching = attachWs(reg.id, ws, c.token, { candidate: true, proof: f.wsProof(c, reg.id) });
  release(); assert.equal(await attaching, true);
  const ready = candidateReady(reg.id, ws);
  assert.equal(typeof ready.then, 'function'); assert.equal(f.record(c.id).status, 'pending');
  assert.equal(candidateReady(reg.id, ws), 'busy');
  release(); assert.equal(await ready, 'promoted');
  assert.equal(getAgentByHost(hostname).id, reg.id);
  // A late "false" for a re-registration is a 401 after the await.
  const d = await f.redeem(keys[1]); verdict = false;
  const refused = f.register(d); release();
  await assert.rejects(refused, { status: 401 });
});
