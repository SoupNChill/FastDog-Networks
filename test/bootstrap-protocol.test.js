import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID, randomBytes, generateKeyPairSync, sign, createHash, privateDecrypt, constants } from 'node:crypto';
import { createBootstrap, exchangeTranscript, OAEP_LABEL, bootstrapHandler, bootstrapMiddleware, clientIp, EXCHANGE_PATH } from '../src/onboard/bootstrap.js';
import { readJson, writeJson, atomicSnapshot, AUTH_LOCK, LOCK_CEILING_MS } from '../src/onboard/json.js';
import { issueCredential, validCredential } from '../src/onboard/credentials.js';
import { createClaims } from '../src/internal/claims.js';
import { createTlsAsk } from '../src/internal/tls-ask.js';
import { createInternalServer } from '../src/internal/server.js';
import { registerAgent, attachWs, closeHost, setOriginStatus, getAgentByHost } from '../src/control/tunnels.js';
import { validOrigin } from '../src/onboard/bootstrap-origin.js';
import { validOrigin as portalOrigin } from '../portal/src/connect-command.js';
import { PassThrough } from 'node:stream';
import { EventEmitter } from 'node:events';
const tid = 't_aaaaaaaaaaaaaaaaaaaa', other = 't_bbbbbbbbbbbbbbbbbbbb';
const hostname = 'app.example.test', audience = 'https://edge.example.test';
const fakeSecret = () => randomBytes(32).toString('hex');
const keys = [0, 1].map(() => generateKeyPairSync('rsa', { modulusLength: 3072 }));
function fixture(t, extra = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bootstrap-test-'));
  t.after(() => { fs.rmSync(directory, { recursive: true, force: true }); closeHost(hostname); });
  let time = Date.now();
  const active = issueCredential({ tenant_id: tid, hostname }, directory, () => time);
  writeJson('tenant_hostnames.json', [{ tenant_id: tid, hostname, status: 'active', txt_value: fakeSecret(), verified_at: new Date(time).toISOString(), created_at: new Date(time).toISOString(), credential_id: active.id }], 0o600, directory);
  const options = { bootstrapEnabled: true, bootstrapAudience: audience, dataDir: directory, now: () => time, issuerCheck: async () => true, ...extra };
  const service = createBootstrap(options);
  t.after(() => service.close());
  const issuance = (overrides = {}) => ({ origin: 'http://127.0.0.1:8080', deployment_id: randomUUID(), issuance_id: randomUUID(), issuer: { kind: 'session', id: randomUUID(), authorization_generation: 1 }, ...overrides });
  function request(code, issued, overrides = {}, key = keys[0]) {
    const body = { hostname, origin: issued.origin, deployment_id: issued.deployment_id, request_id: randomUUID(), recipient_public_key: key.publicKey.export({ type: 'spki', format: 'pem' }), agent_version: '1.2.3', ...overrides };
    body.proof = sign('sha256', exchangeTranscript(audience, createHash('sha256').update(code).digest('hex'), body), { key: key.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }).toString('base64url');
    return body;
  }
  return { directory, active, options, service, issuance, request, advance: (ms) => { time += ms; }, issue: () => service.issue(tid, hostname, issuance()) };
}
const rejects = (fn, status, code) => assert.rejects(fn, (e) => e.status === status && (!code || e.code === code));
function invoke(handler, { method = 'POST', url = EXCHANGE_PATH, body = {}, headers = {} } = {}) {
  const req = new PassThrough(); Object.assign(req, { method, url, headers, socket: { remoteAddress: '127.0.0.1' } });
  const res = new EventEmitter(); res.writableEnded = false;
  return new Promise((resolve, reject) => {
    res.writeHead = (status, headers) => { res.statusCode = status; res.headers = headers; };
    res.end = (raw = '') => { res.writableEnded = true; res.emit('finish'); resolve({ status: res.statusCode, headers: res.headers, body: raw ? JSON.parse(raw) : null }); };
    Promise.resolve(handler(req, res)).catch(reject);
    req.end(typeof body === 'string' ? body : JSON.stringify(body));
  });
}

test('issuance is scoped, idempotent, hashed, cancels older codes and charges shared rotation budgets', async (t) => {
  const f = fixture(t); const body = f.issuance(); const issued = f.service.issue(tid, hostname, body);
  assert.match(issued.code, /^fdab_[\w-]{43}$/);
  assert.equal(Date.parse(issued.expires_at) - f.options.now(), 900000);
  assert.equal(f.service.issue(tid, hostname, body).code, undefined);
  assert.equal(f.service.status(tid, hostname, body.issuance_id).code, undefined);
  for (const [tenant, host] of [[other, hostname], [tid, 'other.example.test']]) assert.throws(() => f.service.status(tenant, host, body.issuance_id), { status: 404, code: 'hostname_not_found' });
  assert.throws(() => f.service.status(tid, hostname, randomUUID()), { status: 404, code: 'bootstrap_not_found' });
  assert.throws(() => f.service.issue(other, hostname, body), { status: 404 });
  const newer = f.issue();
  await rejects(() => f.service.exchange(issued.code, f.request(issued.code, issued), 'ip'), 401);
  assert.equal(f.service.status(tid, hostname, issued.issuance_id).status, 'cancelled');
  const claims = createClaims(f.options, () => {});
  for (let i = 0; i < 3; i++) claims.rotate(tid, hostname);
  assert.throws(() => f.issue(), { status: 429 });
  await rejects(() => f.service.exchange(newer.code, f.request(newer.code, newer), 'ip'), 401);
  assert.ok(!fs.readFileSync(path.join(f.directory, 'agent-auth-state.json'), 'utf8').includes(issued.code));
});

test('exchange decrypts to one pending credential, retries are identical, old active auth remains, expiry revokes', async (t) => {
  const f = fixture(t); const issued = f.issue(); const body = f.request(issued.code, issued);
  f.advance(899999);
  const result = await f.service.exchange(issued.code, body, 'ip');
  const token = privateDecrypt({ key: keys[0].privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: OAEP_LABEL }, Buffer.from(result.encrypted_token, 'base64url')).toString();
  assert.match(token, /^[a-f0-9]{64}$/);
  assert.equal(validCredential(token, hostname, f.directory, f.options.now), false);
  assert.equal(validCredential(f.active.token, hostname, f.directory, f.options.now), true);
  assert.throws(() => registerAgent({ hostname, localUpstream: issued.origin, token, expectedToken: fakeSecret(), dataDir: f.directory }), { status: 401 });
  f.advance(1);
  assert.deepEqual(await f.service.exchange(issued.code, body, 'ip'), result);
  assert.deepEqual(await createBootstrap(f.options).exchange(issued.code, body, 'ip'), result);
  await rejects(() => f.service.exchange(issued.code, f.request(issued.code, issued, { request_id: body.request_id }, keys[1]), 'ip'), 409);
  await rejects(() => f.service.exchange(issued.code, f.request(issued.code, issued), 'ip'), 409);
  await rejects(() => f.service.exchange(issued.code, f.request(issued.code, issued, { origin: 'http://127.0.0.1:9090' }), 'ip'), 401);
  f.advance(119999);
  await rejects(() => f.service.exchange(issued.code, body, 'ip'), 410);
  const records = readJson('agent-credentials.json', [], f.directory);
  assert.equal(records.length, 2);
  assert.ok(records.find((r) => r.id === result.credential_id).revoked_at);
  assert.equal(validCredential(f.active.token, hostname, f.directory, f.options.now), true);
  assert.ok(!fs.readFileSync(path.join(f.directory, 'agent-auth-state.json'), 'utf8').includes(token));
});

test('malformed fields, altered fields, wrong proof, unknown code and exact TTL boundary', async (t) => {
  const f = fixture(t); const issued = f.issue(); const body = f.request(issued.code, issued);
  for (const patch of [{ agent_version: '1234.1.1' }, { agent_version: '1.2.3-beta' }, { recipient_public_key: fakeSecret() }, { origin: 'http://169.254.1.1:8080' }, { extra: 'x' }]) await rejects(() => f.service.exchange(issued.code, { ...body, ...patch }, 'ip'), 400);
  await rejects(() => f.service.exchange(issued.code, { ...body, request_id: randomUUID() }, 'ip'), 401);
  await rejects(() => f.service.exchange(issued.code, { ...body, recipient_public_key: keys[1].publicKey.export({ type: 'spki', format: 'pem' }) }, 'ip'), 401);
  await rejects(() => f.service.exchange(fakeSecret(), body, 'ip'), 401);
  f.advance(900000);
  await rejects(() => f.service.exchange(issued.code, f.request(issued.code, issued, { deployment_id: randomUUID() }), 'ip'), 401);
  await rejects(() => f.service.exchange(issued.code, body, 'ip'), 410);
});

test('issuer missing, false, throwing, and suspension during an in-flight check all fail closed', async (t) => {
  for (const issuerCheck of [undefined, async () => undefined, async () => { throw new Error(fakeSecret()); }]) {
    const f = fixture(t, { issuerCheck }); const issued = f.issue();
    await rejects(() => f.service.exchange(issued.code, f.request(issued.code, issued), 'ip'), 503);
    assert.equal(readJson('agent-credentials.json', [], f.directory).length, 1);
  }
  const denied = fixture(t, { issuerCheck: async () => false }); const deniedCode = denied.issue();
  await rejects(() => denied.service.exchange(deniedCode.code, denied.request(deniedCode.code, deniedCode), 'ip'), 401);
  let resolve; const f = fixture(t, { issuerCheck: () => new Promise((r) => { resolve = r; }) }); const issued = f.issue();
  const pending = f.service.exchange(issued.code, f.request(issued.code, issued), 'ip');
  createClaims(f.options, () => {}).suspendTenant(tid); resolve(true);
  await rejects(() => pending, 401);
  assert.throws(() => f.service.status(tid, hostname, issued.issuance_id), { status: 404, code: 'hostname_not_found' });
  assert.ok(readJson('agent-bootstrap.json', [], f.directory).codes.every((c) => c.cancelled));
});

test('cancel, rotate, detach and suspend remove recovery and revoke pending credentials', async (t) => {
  for (const action of ['cancel', 'rotate', 'delete', 'suspendTenant']) {
    const f = fixture(t); const issued = f.issue(); const body = f.request(issued.code, issued);
    await f.service.exchange(issued.code, body, 'ip');
    if (action === 'cancel') f.service.cancel(tid, hostname);
    else createClaims(f.options, () => {})[action](tid, hostname);
    await rejects(() => f.service.exchange(issued.code, body, 'ip'), 401);
    assert.ok(readJson('agent-credentials.json', [], f.directory).filter((r) => r.status === 'pending').every((r) => r.revoked_at));
  }
});

test('persisted code limits, IP/global limits, Retry-After and capacity refuse admission', async (t) => {
  const f = fixture(t); const issued = f.issue(); const body = f.request(issued.code, issued);
  for (let i = 0; i < 10; i++) await f.service.exchange(issued.code, body, 'ip');
  await rejects(() => createBootstrap(f.options).exchange(issued.code, body, 'ip'), 429);
  f.advance(60000);
  await f.service.exchange(issued.code, body, 'ip');
  const g = fixture(t);
  for (let i = 0; i < 30; i++) await rejects(() => g.service.exchange('unknown', body, 'ip'), 401);
  await assert.rejects(() => g.service.exchange('unknown', body, 'ip'), (e) => e.status === 429 && e.retry_after === 60);
  // Per-IP rejections never consume global capacity: one flooding IP leaves 270 admissions for everyone else.
  for (let i = 0; i < 500; i++) await rejects(() => g.service.exchange('unknown', body, 'ip'), 429);
  for (let i = 0; i < 270; i++) await rejects(() => g.service.exchange('unknown', body, `ip${i}`), 401);
  await assert.rejects(() => g.service.exchange('unknown', body, 'last'), (e) => e.status === 429 && e.retry_after === 60);
  g.advance(60000);
  await rejects(() => g.service.exchange('unknown', body, 'last'), 401);
  const h = fixture(t, { limiterCapacity: 2 });
  await rejects(() => h.service.exchange('unknown', body, 'a'), 401);
  await rejects(() => h.service.exchange('unknown', body, 'b'), 429);
});

test('atomic snapshot failure before rename preserves old data and cleans temporary files', (t) => {
  const f = fixture(t); const file = path.join(f.directory, 'crash.json');
  atomicSnapshot(file, { version: 1 });
  assert.throws(() => atomicSnapshot(file, { version: 2 }, () => { throw new Error('simulated_failure'); }));
  assert.deepEqual(JSON.parse(fs.readFileSync(file)), { version: 1 });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.ok(!fs.readdirSync(f.directory).some((s) => s.endsWith('.tmp')));
});

test('key binding is immutable and fresh upgrade validation rejects changed auth state', (t) => {
  const f = fixture(t);
  const reg = registerAgent({ hostname, localUpstream: 'http://127.0.0.1:8080', token: f.active.token, expectedToken: fakeSecret(), dataDir: f.directory });
  const records = readJson('agent-credentials.json', [], f.directory); records[0].key_fingerprint = fakeSecret();
  writeJson('agent-credentials.json', records, 0o600, f.directory);
  assert.equal(validCredential(f.active.token, hostname, f.directory), false);
  assert.equal(attachWs(reg.id, {}, f.active.token), false);
  delete records[0].key_fingerprint;
  assert.throws(() => writeJson('agent-credentials.json', records, 0o600, f.directory), /immutable_key_binding/);
  fs.writeFileSync(path.join(f.directory, 'agent-auth-state.json'), '{');
  assert.equal(attachWs(reg.id, {}, f.active.token), false);
});

test('version validator matches heartbeat and edge origin rules match portal', (t) => {
  const f = fixture(t); const reg = registerAgent({ hostname, localUpstream: 'http://127.0.0.1:8080', token: f.active.token, expectedToken: fakeSecret(), dataDir: f.directory });
  for (const version of ['1.2.3', '123.0.999']) { setOriginStatus(reg.id, { agent_version: version }); assert.equal(getAgentByHost(hostname).agentVersion, version); }
  for (const version of ['1.2', '1.2.3-beta', '1000.2.3']) { setOriginStatus(reg.id, { agent_version: version }); assert.equal(getAgentByHost(hostname).agentVersion, '123.0.999'); }
  for (const origin of ['127.0.0.1:8080', 'http://localhost:8080/', 'http://10.0.0.1:9000', 'http://[::1]:8080', 'http://169.254.1.1:8080', 'http://100.64.0.1:8080', 'http://[fe80::1]:8080', 'https://app.example.test:8080', 'http://localhost:80', 'http://127.0.0.1:8080/a']) assert.equal(validOrigin(origin), portalOrigin(origin));
});

test('HTTP handlers enforce auth, scope, flag, method, cap, canonical path and redact errors', async (t) => {
  const f = fixture(t); const portalKey = fakeSecret(); const logs = [];
  const server = createInternalServer({ ...f.options, portalKey, agentToken: fakeSecret(), logger: (entry) => logs.push(entry) });
  const handle = server.listeners('request')[0]; const url = `/internal/v1/tenants/${tid}/hostnames/${hostname}/bootstraps`;
  assert.equal((await invoke(handle, { url, body: f.issuance() })).status, 401);
  const headers = { 'x-fastdog-portal-key': portalKey };
  const issued = await invoke(handle, { url, headers, body: f.issuance() }); assert.equal(issued.status, 200);
  const status = await invoke(handle, { url: `${url}/${issued.body.issuance_id}`, method: 'GET', headers }); assert.equal(status.body.code, undefined); assert.equal(status.status, 200);
  const wrong = await invoke(handle, { url: `${url.replace(tid, other)}/${issued.body.issuance_id}`, method: 'GET', headers }); assert.equal(wrong.status, 404);
  const publicHandler = bootstrapHandler(f.service);
  assert.equal((await invoke(publicHandler, { method: 'GET' })).status, 405);
  assert.equal((await invoke(publicHandler, { url: `${EXCHANGE_PATH}?x=1` })).status, 404);
  assert.equal((await invoke(publicHandler, { body: 'x'.repeat(16385) })).status, 413);
  assert.equal((await invoke(publicHandler, { body: '{' })).status, 401);
  const body = f.request(issued.body.code, issued.body);
  const result = await invoke(publicHandler, { body, headers: { authorization: `Bearer ${issued.body.code}` } }); assert.equal(result.status, 200); assert.equal(result.headers['cache-control'], 'no-store');
  const off = createBootstrap({ bootstrapEnabled: false, dataDir: f.directory });
  assert.equal((await invoke(bootstrapHandler(off))).status, 404);
  const offServer = createInternalServer({ ...f.options, bootstrapEnabled: false, portalKey, agentToken: fakeSecret() });
  assert.equal((await invoke(offServer.listeners('request')[0], { url, headers, body: f.issuance() })).status, 404);
  assert.ok(!JSON.stringify(logs).includes(issued.body.code)); assert.ok(!JSON.stringify(logs).includes(portalKey));
});

test('claim limit survives code changes and the absolute issuance ceiling is independent', async (t) => {
  const f = fixture(t);
  for (let c = 0; c < 3; c++) {
    const issued = f.issue(); const body = f.request(issued.code, issued);
    for (let i = 0; i < 10; i++) await f.service.exchange(issued.code, body, `ip${c}`);
  }
  const issued = f.issue();
  await rejects(() => f.service.exchange(issued.code, f.request(issued.code, issued), 'next'), 429);
  f.advance(60000);
  await f.service.exchange(issued.code, f.request(issued.code, issued), 'next');
  const state = readJson('agent-bootstrap.json', [], f.directory);
  state.budgets[hostname].rotations = 0; state.budgets[hostname].issuances = 8;
  writeJson('agent-bootstrap.json', state, 0o600, f.directory);
  assert.throws(() => f.issue(), { status: 429 });
});

test('disabled service leaves legacy storage unchanged and legacy active credentials authenticate', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bootstrap-off-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const credential = issueCredential({ hostname }, directory);
  const before = fs.readFileSync(path.join(directory, 'agent-credentials.json'), 'utf8');
  const service = createBootstrap({ dataDir: directory, bootstrapEnabled: false });
  assert.throws(() => service.issue(tid, hostname, {}), { status: 404 });
  assert.equal(fs.readFileSync(path.join(directory, 'agent-credentials.json'), 'utf8'), before);
  assert.ok(!fs.existsSync(path.join(directory, 'agent-auth-state.json')));
  assert.equal(validCredential(credential.token, hostname, directory), true);
});

test('console and HTTP errors never reveal generated code, token, key, ciphertext or thrown secrets', async (t) => {
  const sentinel = fakeSecret(); const f = fixture(t, { issuerCheck: async () => { throw new Error(sentinel); } });
  const issued = f.issue(); const body = f.request(issued.code, issued); const logs = [];
  const originals = Object.fromEntries(['log', 'warn', 'error', 'info'].map((name) => [name, console[name]]));
  try {
    for (const name of Object.keys(originals)) console[name] = (...args) => logs.push(args);
    const response = await invoke(bootstrapHandler(f.service), { body, headers: { authorization: `Bearer ${issued.code}` } });
    assert.deepEqual(response.body, { error: 'bootstrap_unavailable' });
    const captured = JSON.stringify({ logs, response });
    for (const secret of [sentinel, issued.code, f.active.token, body.recipient_public_key, body.proof]) assert.ok(!captured.includes(secret));
  } finally { Object.assign(console, originals); }
});

test('pending and held records reject active auth even without a key fingerprint', (t) => {
  const f = fixture(t);
  for (const status of ['pending', 'held']) {
    const records = readJson('agent-credentials.json', [], f.directory); records[0].status = status;
    writeJson('agent-credentials.json', records, 0o600, f.directory);
    assert.equal(validCredential(f.active.token, hostname, f.directory, f.options.now), false);
    assert.throws(() => registerAgent({ hostname, localUpstream: 'http://127.0.0.1:8080', token: f.active.token, expectedToken: fakeSecret(), dataDir: f.directory }), { status: 401 });
  }
});

test('malformed RSA keys and null origin are invalid requests without consumption', async (t) => {
  const f = fixture(t); const issued = f.issue(); const body = f.request(issued.code, issued);
  const small = generateKeyPairSync('rsa', { modulusLength: 2048 });
  for (const patch of [{ origin: null }, { recipient_public_key: small.publicKey.export({ type: 'spki', format: 'pem' }) }, { recipient_public_key: keys[0].publicKey.export({ type: 'pkcs1', format: 'pem' }) }]) await rejects(() => f.service.exchange(issued.code, { ...body, ...patch }, 'ip'), 400);
  assert.equal(f.service.status(tid, hostname, issued.issuance_id).status, 'pending');
});


test('combined claim suspension invalidates cached TLS ownership without changing TLS defaults', async (t) => {
  const f = fixture(t);
  const ask = createTlsAsk({ ...f.options, tlsAskEnabled: true, liveVerify: false, attachTarget: 'attach.example.test', altAttachTarget: 'edge.example.test', reservedSuffixes: [] });
  assert.equal((await ask(hostname)).status, 200);
  createClaims(f.options, () => {}).suspendTenant(tid);
  assert.equal((await ask(hostname)).status, 404);
});

test('five-second exchange deadline aborts an issuer check without consuming the code', async (t) => {
  let release;
  const f = fixture(t, { issuerCheck: () => new Promise((resolve) => { release = resolve; }) });
  const issued = f.issue(); const body = f.request(issued.code, issued);
  const started = Date.now();
  const response = await invoke(bootstrapHandler(f.service), { body, headers: { authorization: `Bearer ${issued.code}` } });
  assert.equal(response.status, 503);
  assert.ok(Date.now() - started >= 4900 && Date.now() - started < 6500);
  release(true);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.service.status(tid, hostname, issued.issuance_id).status, 'pending');
  assert.equal(readJson('agent-credentials.json', [], f.directory).length, 1);
});


test('concurrent matching exchanges commit one pending credential and one ciphertext', async (t) => {
  const f = fixture(t); const issued = f.issue(); const body = f.request(issued.code, issued);
  const responses = await Promise.all([f.service.exchange(issued.code, body, 'a'), f.service.exchange(issued.code, body, 'b')]);
  assert.deepEqual(responses[0], responses[1]);
  assert.equal(readJson('agent-credentials.json', [], f.directory).filter((r) => r.status === 'pending').length, 1);
});


test('trusted last-hop IP buckets are separate and external peers ignore forwarding', async (t) => {
  assert.equal(clientIp({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-for': '192.0.2.1, 192.0.2.2' } }), '192.0.2.2');
  assert.equal(clientIp({ socket: { remoteAddress: '192.0.2.3' }, headers: { 'x-forwarded-for': '192.0.2.1' } }), '192.0.2.3');
  const f = fixture(t); const handler = bootstrapHandler(f.service);
  for (let i = 0; i < 30; i++) assert.equal((await invoke(handler, { body: '{', headers: { 'x-forwarded-for': `192.0.2.${i}, 192.0.2.1` } })).status, 401);
  assert.equal((await invoke(handler, { headers: { 'x-forwarded-for': '192.0.2.1' } })).status, 429);
  assert.equal((await invoke(handler, { headers: { 'x-forwarded-for': '192.0.2.2' } })).status, 401);
});

test('loopback peers without forwarding share a small unattributed bucket separate from forwarded clients', async (t) => {
  assert.equal(clientIp({ socket: { remoteAddress: '127.0.0.1' }, headers: {} }), null);
  const f = fixture(t); const handler = bootstrapHandler(f.service);
  for (let i = 0; i < 10; i++) assert.equal((await invoke(handler, { body: '{' })).status, 401);
  assert.equal((await invoke(handler, { body: '{' })).status, 429);
  assert.equal((await invoke(handler, { body: '{', headers: { 'x-forwarded-for': '127.0.0.1' } })).status, 401);
  assert.equal((await invoke(handler, { body: '{', headers: { 'x-forwarded-for': '192.0.2.9' } })).status, 401);
});

test('limiter sweeps expired entries in insertion order and keeps the capacity cap', async (t) => {
  const f = fixture(t, { limiterCapacity: 101 }); const body = {};
  for (let i = 0; i < 100; i++) await rejects(() => f.service.exchange('unknown', body, `a${i}`), 401);
  await rejects(() => f.service.exchange('unknown', body, 'late'), 429);
  f.advance(60000);
  // Each request sweeps a bounded prefix, so expired entries drain without a full scan and new clients are admitted.
  for (let i = 0; i < 40; i++) await rejects(() => f.service.exchange('unknown', body, `b${i}`), 401);
});

test('status requires current hostname ownership', (t) => {
  const f = fixture(t); const issued = f.issue();
  writeJson('tenant_hostnames.json', readJson('tenant_hostnames.json', [], f.directory).map((r) => ({ ...r, tenant_id: other })), 0o600, f.directory);
  assert.throws(() => f.service.status(tid, hostname, issued.issuance_id), { status: 404, code: 'hostname_not_found' });
});

test('flag-off reads and writes of non-auth files do no combined-state probing', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'bootstrap-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const probe = t.mock.method(fs, 'existsSync');
  writeJson('other.json', { a: 1 }, 0o600, directory);
  assert.equal(probe.mock.callCount(), 0);
  assert.deepEqual(readJson('other.json', null, directory), { a: 1 });
  assert.deepEqual(probe.mock.calls.map((c) => path.basename(c.arguments[0])), ['other.json']);
});

test('exchange middleware preserves downstream routing off and scopes enabled authority exactly', async (t) => {
  for (const enabled of [false, true]) {
    const f = fixture(t, { bootstrapEnabled: enabled });
    const middleware = bootstrapMiddleware(f.service);
    const handler = (req, res) => middleware(req, res, () => { res.writeHead(299, {}); res.end('{}'); });
    for (const url of [EXCHANGE_PATH, `${EXCHANGE_PATH}X`, `${EXCHANGE_PATH}?x=1`]) {
      assert.equal((await invoke(handler, { url, headers: { host: hostname } })).status, 299);
      assert.equal((await invoke(handler, { url, headers: { host: 'edge.example.test' } })).status, enabled && url === EXCHANGE_PATH ? 401 : 299);
    }
  }
});

test('flag-off legacy upgrade retains registration authority after revocation', (t) => {
  const f = fixture(t, { bootstrapEnabled: false });
  const reg = registerAgent({ hostname, localUpstream: 'http://127.0.0.1:8080', token: f.active.token, expectedToken: fakeSecret(), dataDir: f.directory });
  const records = readJson('agent-credentials.json', [], f.directory); records[0].revoked_at = new Date().toISOString();
  writeJson('agent-credentials.json', records, 0o600, f.directory);
  assert.equal(attachWs(reg.id, {}, f.active.token), true);
});

test('retention prunes terminal records after 24h, old budgets, and refuses the live cap atomically', (t) => {
  const f = fixture(t); const issued = f.issue();
  f.advance(900000); f.service.status(tid, hostname, issued.issuance_id);
  let state = readJson('agent-bootstrap.json', [], f.directory);
  assert.ok(state.codes[0].tombstone_at); assert.equal(state.codes[0].issuer, undefined);
  state.budgets['old.example.test'] = { day: 0, rotations: 1, issuances: 1 };
  writeJson('agent-bootstrap.json', state, 0o600, f.directory);
  f.advance(86400000); f.issue();
  state = readJson('agent-bootstrap.json', [], f.directory);
  assert.equal(state.codes.length, 1); assert.equal(state.budgets['old.example.test'], undefined);
  const live = state.codes[0];
  state.codes = Array.from({ length: 10000 }, (_, i) => ({ ...live, issuance_id: `issued_${i}` }));
  writeJson('agent-bootstrap.json', state, 0o600, f.directory);
  const before = fs.readFileSync(path.join(f.directory, 'agent-auth-state.json'), 'utf8');
  assert.throws(() => f.issue(), { status: 503 });
  assert.equal(fs.readFileSync(path.join(f.directory, 'agent-auth-state.json'), 'utf8'), before);
});

test('idle periodic sweep purges recovery and is disabled with the flag', async (t) => {
  const f = fixture(t, { sweepIntervalMs: 10 }); const issued = f.issue();
  await f.service.exchange(issued.code, f.request(issued.code, issued), 'ip');
  f.advance(120000);
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.equal(readJson('agent-bootstrap.json', [], f.directory).codes[0].response, undefined);
  assert.ok(readJson('agent-credentials.json', [], f.directory).at(-1).revoked_at);
  const off = fixture(t, { bootstrapEnabled: false, sweepIntervalMs: 10 });
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.ok(!fs.existsSync(path.join(off.directory, 'agent-auth-state.json')));
});

test('stale empty lock recovers while a live writer lock is preserved', (t) => {
  const f = fixture(t); const lock = path.join(f.directory, AUTH_LOCK);
  fs.writeFileSync(lock, ''); fs.utimesSync(lock, new Date(0), new Date(0));
  f.issue(); assert.ok(!fs.existsSync(lock));
  fs.writeFileSync(lock, '2147483647');
  f.issue(); assert.ok(!fs.existsSync(lock));
  fs.writeFileSync(lock, String(process.pid));
  assert.throws(() => f.issue(), { status: 503 });
  assert.equal(fs.readFileSync(lock, 'utf8'), String(process.pid));
});

test('nonce locks reap dead or over-age holders and preserve fresh live ones', (t) => {
  const f = fixture(t); const lock = path.join(f.directory, AUTH_LOCK);
  const holder = (pid, created) => JSON.stringify({ pid, nonce: randomUUID(), created });
  fs.writeFileSync(lock, holder(2147483647, Date.now()));
  f.issue(); assert.ok(!fs.existsSync(lock));
  const live = holder(process.pid, Date.now());
  fs.writeFileSync(lock, live);
  assert.throws(() => f.issue(), { status: 503 }); assert.equal(fs.readFileSync(lock, 'utf8'), live);
  // A reused live pid cannot pin the lock beyond the ceiling.
  fs.writeFileSync(lock, holder(process.pid, Date.now() - LOCK_CEILING_MS - 1));
  f.issue(); assert.ok(!fs.existsSync(lock));
});

test('a lock released between the failed open and the read is retried, not reported unavailable', (t) => {
  const f = fixture(t); const lock = path.join(f.directory, AUTH_LOCK);
  fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, nonce: randomUUID(), created: Date.now() }));
  const read = fs.readFileSync; let raced = false;
  t.mock.method(fs, 'readFileSync', function (file, ...rest) {
    if (file === lock && !raced) { raced = true; fs.unlinkSync(lock); }
    return read.call(this, file, ...rest);
  });
  f.issue();
  assert.ok(raced); assert.ok(!fs.existsSync(lock));
});

test('a reap claim left by a crashed reaper is recovered after the ceiling; a fresh claim stays busy', (t) => {
  const f = fixture(t); const lock = path.join(f.directory, AUTH_LOCK); const claim = `${lock}.reap`;
  fs.writeFileSync(lock, JSON.stringify({ pid: 2147483647, nonce: randomUUID(), created: Date.now() }));
  fs.linkSync(lock, claim);
  assert.throws(() => f.issue(), { status: 503 });
  assert.ok(fs.existsSync(claim));
  const real = Date.now; t.mock.method(Date, 'now', () => real() + LOCK_CEILING_MS + 1000);
  f.issue();
  assert.ok(!fs.existsSync(claim)); assert.ok(!fs.existsSync(lock));
});

test('a live writer that releases during the bounded retries does not surface as unavailable', (t) => {
  const f = fixture(t); const lock = path.join(f.directory, AUTH_LOCK);
  fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, nonce: randomUUID(), created: Date.now() }));
  const open = fs.openSync; let attempts = 0;
  t.mock.method(fs, 'openSync', function (file, ...rest) {
    if (file === lock && ++attempts === 2) fs.unlinkSync(lock);
    return open.call(this, file, ...rest);
  });
  f.issue();
  assert.ok(attempts > 2); assert.ok(!fs.existsSync(lock));
});

test('unknown codes return uniform unauthorized even with malformed fields or keys', async (t) => {
  const f = fixture(t);
  for (const body of [null, {}, { recipient_public_key: 'malformed' }]) await rejects(() => f.service.exchange('unknown', body, 'ip'), 401, 'unauthorized');
});

test('cancelled and used recovery tombstones are retained for 24h then purged', async (t) => {
  for (const consumed of [false, true]) {
    const f = fixture(t); const issued = f.issue();
    if (consumed) { await f.service.exchange(issued.code, f.request(issued.code, issued), 'ip'); f.advance(120000); }
    else f.service.cancel(tid, hostname);
    f.service.status(tid, hostname, issued.issuance_id);
    const retired = readJson('agent-bootstrap.json', [], f.directory).codes[0];
    assert.ok(retired.tombstone_at); assert.equal(retired.response, undefined);
    f.advance(86400000);
    assert.throws(() => f.service.status(tid, hostname, issued.issuance_id), { status: 404 });
    assert.equal(readJson('agent-bootstrap.json', [], f.directory).codes.length, 0);
  }
});

test('startup migration recovers an abandoned lock', (t) => {
  const f = fixture(t, { bootstrapEnabled: false });
  fs.writeFileSync(path.join(f.directory, AUTH_LOCK), '2147483647');
  const enabled = createBootstrap({ ...f.options, bootstrapEnabled: true });
  t.after(() => enabled.close());
  assert.ok(fs.existsSync(path.join(f.directory, 'agent-auth-state.json')));
  assert.ok(!fs.existsSync(path.join(f.directory, AUTH_LOCK)));
});
