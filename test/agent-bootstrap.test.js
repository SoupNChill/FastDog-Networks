// Agent state tests (bootstrap plan section 10): startup state machine, durable persistence and the exchange client.
// The exchange "edge" is the real createBootstrap service called in-process; no sockets are opened here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { randomUUID, randomBytes, createHash, createPublicKey, createPrivateKey, verify, constants } from 'node:crypto';
import { createBootstrap, exchangeTranscript as edgeExchangeTranscript } from '../src/onboard/bootstrap.js';
import { writeJson } from '../src/onboard/json.js';
import { issueCredential } from '../src/onboard/credentials.js';
import { proofTranscript as edgeProofTranscript, parseProof, verifyAgentProof, createNonceCache } from '../src/control/agent-proof.js';
import { validAgentVersion } from '../src/control/agent-version.js';
import { startAgent, AGENT_VERSION, currentOriginStatus, MAX_CREDENTIAL_REJECTIONS } from '../agent/index.js';
import { readState, writeState, acquireLock, atomicWrite, STATE_FILE, LOCK_FILE } from '../agent/state.js';
import { readSettings, pinnedEdge, loadPins, KNOWN_AGENT_ENV } from '../agent/config.js';
import { generateKey, exchangeTranscript, proofTranscript, proofHeader, dialTarget, tlsOptions, sha256 } from '../agent/protocol.js';
import { REDEEM_HORIZON_MS } from '../agent/bootstrap.js';

const tid = 't_aaaaaaaaaaaaaaaaaaaa', hostname = 'app.example.test', audience = 'https://edge.example.test';
const origin = 'http://127.0.0.1:8080', pins = [audience];
const keys = [generateKey(), generateKey()];
const fakeCode = () => `fdab_${randomBytes(32).toString('base64url')}`;

function tmp(t, prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// Real edge exchange service plus an issued code, and a request function speaking its HTTP status semantics.
function edge(t, { faults = [] } = {}) {
  const directory = tmp(t, 'agent-edge-');
  const active = issueCredential({ tenant_id: tid, hostname }, directory);
  writeJson('tenant_hostnames.json', [{ tenant_id: tid, hostname, status: 'active', txt_value: randomBytes(8).toString('hex'),
    verified_at: new Date().toISOString(), created_at: new Date().toISOString(), credential_id: active.id }], 0o600, directory);
  const service = createBootstrap({ bootstrapEnabled: true, bootstrapAudience: audience, dataDir: directory, issuerCheck: async () => true });
  t.after(() => service.close());
  const issued = service.issue(tid, hostname, { origin, deployment_id: randomUUID(), issuance_id: randomUUID(), issuer: { kind: 'session', id: randomUUID(), authorization_generation: 1 } });
  const calls = [];
  async function request(url, { method, headers, body }) {
    calls.push({ url, method, headers, body: JSON.parse(body) });
    const fault = faults.shift();
    if (fault === 'network') throw new Error('ECONNRESET');
    if (typeof fault === 'object') return { status: fault.status, headers: fault.headers ?? {}, body: Buffer.from('{}') };
    const code = /^Bearer (.+)$/.exec(headers.authorization)?.[1];
    try {
      const result = await service.exchange(code, JSON.parse(body), '127.0.0.1');
      if (fault === 'lost') throw new Error('response lost after commit');
      return { status: 200, headers: {}, body: Buffer.from(JSON.stringify(result)) };
    } catch (e) {
      if (!e.status) throw e;
      return { status: e.status, headers: e.retry_after ? { 'retry-after': String(e.retry_after) } : {}, body: Buffer.from(JSON.stringify({ error: e.code })) };
    }
  }
  return { directory, service, issued, calls, request, active };
}

function envFor(issued, extra = {}) {
  return { AGENT_BOOTSTRAP: issued.code, AGENT_HOSTNAME: hostname, AGENT_NAME: hostname, AGENT_LOCAL_UPSTREAM: origin,
    AGENT_DEPLOYMENT_ID: issued.deployment_id, EDGE_HTTP_URL: audience, EDGE_WS_URL: `wss://edge.example.test/_fastdog/tunnel`, PATH: '/usr/bin', ...extra };
}

// Runs startAgent without opening the tunnel: the reconnect loop is captured, exits and logs are recorded.
async function start(t, { env, stateDir, request, keygen = () => keys[0], ...rest }) {
  const exits = [], lines = [];
  const log = { log: (m) => lines.push(m), warn: (m) => lines.push(m), error: (m) => lines.push(m) };
  let loopFns;
  const result = await startAgent({ env, stateDir, pins, request, keygen, exit: (code) => exits.push(code), log, sleep: async () => {},
    loop: (fns) => { loopFns = fns; return new Promise(() => {}); }, lockOptions: { staleMs: 60000, waitMs: 50 }, ...rest });
  t.after(() => result.stop?.());
  return { result, exits, lines, loopFns, output: lines.join('\n') };
}

const stateFile = (dir) => path.join(dir, STATE_FILE);
const secretsIn = (text, secrets) => secrets.filter((s) => s && text.includes(s));

function activeState(issued, overrides = {}) {
  return { schema: 1, status: 'active', hostname, origin, audience, deployment_id: issued.deployment_id, private_key: keys[0].privateKey,
    key_fingerprint: keys[0].fingerprint, credential_id: randomUUID(), token: randomBytes(32).toString('hex'), promoted: false, ...overrides };
}

test('wire formats match the edge byte for byte and agent proofs verify on the edge', () => {
  const body = { hostname, origin, deployment_id: 'd', request_id: 'r', recipient_public_key: keys[0].publicKey, agent_version: '1.2.3' };
  assert.deepEqual(exchangeTranscript(audience, 'a'.repeat(64), body), edgeExchangeTranscript(audience, 'a'.repeat(64), body));
  const args = { method: 'GET', target: '/_fastdog/tunnel?agentId=x&candidate=1', audience, credentialId: 'c', timestamp: 1, nonce: 'n', body: Buffer.from('b') };
  assert.deepEqual(proofTranscript(args), edgeProofTranscript(args));
  const header = proofHeader(keys[0].privateKey, { method: 'POST', target: '/_fastdog/agents/register?candidate=1', audience, credentialId: 'cred', body: Buffer.from('{}') });
  assert.ok(parseProof([header]));
  const der = createPublicKey(keys[0].publicKey).export({ type: 'spki', format: 'der' });
  const record = { id: 'cred', public_key: der.toString('base64'), key_fingerprint: keys[0].fingerprint };
  const context = { values: [header], method: 'POST', target: '/_fastdog/agents/register?candidate=1', audience, body: Buffer.from('{}') };
  assert.equal(verifyAgentProof(context, record, Date.now, createNonceCache()), true);
  assert.equal(verifyAgentProof({ ...context, target: '/_fastdog/agents/register' }, record, Date.now, createNonceCache()), false);
});

test('bootstrap: durable pending state precedes the single exchange; credential persisted 0600 and never placed in the process environment', async (t) => {
  const e = edge(t); const dir = tmp(t, 'agent-state-');
  const envBefore = JSON.stringify(process.env);
  const run = await start(t, { env: envFor(e.issued), stateDir: dir, request: async (...args) => {
    // Durable pending request and key exist before the first network call.
    const pending = readState(dir);
    assert.equal(pending.status, 'pending'); assert.equal(pending.key_fingerprint, keys[0].fingerprint);
    assert.equal(pending.code_digest, sha256(e.issued.code));
    return e.request(...args);
  } });
  assert.deepEqual(run.exits, []);
  assert.equal(run.result.mode, 'key_bound');
  assert.equal(e.calls.length, 1);
  const sent = e.calls[0];
  assert.equal(sent.url, `${audience}/_fastdog/agents/bootstrap/exchange`);
  assert.deepEqual(Object.keys(sent.body).sort(), ['agent_version', 'deployment_id', 'hostname', 'origin', 'proof', 'recipient_public_key', 'request_id']);
  assert.equal(sent.body.agent_version, AGENT_VERSION);
  const saved = readState(dir);
  assert.equal(saved.status, 'active'); assert.equal(saved.promoted, false);
  assert.match(saved.token, /^[0-9a-f]{64}$/);
  assert.equal(saved.private_key, keys[0].privateKey);
  assert.equal(fs.statSync(stateFile(dir)).mode & 0o777, 0o600);
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  assert.deepEqual(fs.readdirSync(dir).filter((n) => n.endsWith('.tmp')), []);
  assert.equal(JSON.stringify(process.env), envBefore);
  assert.deepEqual(secretsIn(JSON.stringify(process.env), [saved.token, e.issued.code]), []);
  assert.deepEqual(secretsIn(run.output, [saved.token, e.issued.code, sent.body.proof, saved.private_key]), []);
  assert.deepEqual(currentOriginStatus(), { credential_mode: 'key_bound', bootstrap_status: 'candidate' });
});

test('persisted credential wins: restart with an expired or unrelated bootstrap code makes no exchange call', async (t) => {
  const e = edge(t); const dir = tmp(t, 'agent-state-');
  const state = activeState(e.issued);
  writeState(dir, state);
  const run = await start(t, { env: envFor(e.issued, { AGENT_BOOTSTRAP: fakeCode() }), stateDir: dir, request: e.request });
  assert.deepEqual(run.exits, []); assert.equal(run.result.mode, 'key_bound'); assert.equal(e.calls.length, 0);
  assert.deepEqual(readState(dir), state);
  // The persisted credential also wins with no bootstrap set at all (normal restart).
  run.result.stop();
  const again = await start(t, { env: envFor(e.issued, { AGENT_BOOTSTRAP: undefined }), stateDir: dir, request: e.request });
  assert.equal(again.result.mode, 'key_bound'); assert.equal(e.calls.length, 0);
});

test('corrupt, unsupported, unsafe or wrong-binding state fails closed without redeeming over it', async (t) => {
  const e = edge(t);
  const cases = {
    corrupt: (dir) => fs.writeFileSync(stateFile(dir), '{not json', { mode: 0o600 }),
    unknown_field: (dir) => fs.writeFileSync(stateFile(dir), JSON.stringify({ ...activeState(e.issued), extra: 1 }), { mode: 0o600 }),
    unsupported_schema: (dir) => fs.writeFileSync(stateFile(dir), JSON.stringify({ ...activeState(e.issued), schema: 2 }), { mode: 0o600 }),
    wrong_fingerprint: (dir) => fs.writeFileSync(stateFile(dir), JSON.stringify(activeState(e.issued, { key_fingerprint: keys[1].fingerprint })), { mode: 0o600 }),
    loose_mode: (dir) => fs.writeFileSync(stateFile(dir), JSON.stringify(activeState(e.issued)), { mode: 0o644 }),
    symlink: (dir) => { const elsewhere = path.join(dir, '..', `${path.basename(dir)}-target.json`); fs.writeFileSync(elsewhere, JSON.stringify(activeState(e.issued)), { mode: 0o600 }); t.after(() => fs.rmSync(elsewhere, { force: true })); fs.symlinkSync(elsewhere, stateFile(dir)); },
    directory: (dir) => fs.mkdirSync(stateFile(dir)),
    other_deployment: (dir) => writeState(dir, activeState(e.issued, { deployment_id: randomUUID() })),
    other_hostname: (dir) => writeState(dir, activeState(e.issued, { hostname: 'other.example.test' })),
    other_origin: (dir) => writeState(dir, activeState(e.issued, { origin: 'http://127.0.0.1:9090' })),
    other_edge: (dir) => writeState(dir, activeState(e.issued, { audience: 'https://other-edge.example.test' })),
  };
  for (const [name, prepare] of Object.entries(cases)) {
    const dir = tmp(t, 'agent-state-'); prepare(dir);
    const before = fs.lstatSync(stateFile(dir));
    const run = await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request });
    assert.deepEqual(run.exits, [1], name);
    assert.match(run.output, /state_(corrupt|unsupported|file_unsafe|binding_mismatch)/, name);
    assert.equal(fs.lstatSync(stateFile(dir)).mtimeMs, before.mtimeMs, name);
    assert.equal(fs.existsSync(path.join(dir, LOCK_FILE)), false, `${name}: lock released`);
  }
  assert.equal(e.calls.length, 0);
});

test('legacy AGENT_TOKEN mode works with or without the state directory and only logs a nonsecret notice', async (t) => {
  const token = randomBytes(32).toString('hex');
  const seeded = tmp(t, 'agent-state-'); fs.writeFileSync(path.join(seeded, '.fastdog-agent-volume'), '', { mode: 0o600 });
  for (const stateDir of [path.join(os.tmpdir(), `absent-${randomUUID()}`), seeded]) {
    const env = { AGENT_TOKEN: token, AGENT_HOSTNAME: hostname, EDGE_HTTP_URL: 'http://127.0.0.1:1', EDGE_WS_URL: 'ws://127.0.0.1:1/_fastdog/tunnel' };
    const run = await start(t, { env, stateDir, request: async () => assert.fail('no exchange in legacy mode') });
    assert.deepEqual(run.exits, []); assert.equal(run.result.mode, 'legacy');
    assert.match(run.output, /compatibility mode is deprecated/);
    assert.ok(!run.output.includes(token));
    assert.deepEqual(currentOriginStatus(), { credential_mode: 'legacy', bootstrap_status: 'none' });
    assert.deepEqual(fs.readdirSync(seeded), ['.fastdog-agent-volume']);
  }
});

test('both secrets without state are rejected; neither fails clearly; values are never printed', async (t) => {
  const e = edge(t); const dir = tmp(t, 'agent-state-');
  const token = randomBytes(32).toString('hex');
  const both = await start(t, { env: envFor(e.issued, { AGENT_TOKEN: token }), stateDir: dir, request: e.request });
  assert.deepEqual(both.exits, [1]); assert.match(both.output, /ambiguous_config/);
  const neither = await start(t, { env: envFor(e.issued, { AGENT_BOOTSTRAP: undefined }), stateDir: dir, request: e.request });
  assert.deepEqual(neither.exits, [1]); assert.match(neither.output, /AGENT_TOKEN is required/);
  assert.deepEqual(fs.readdirSync(dir), []);
  assert.equal(e.calls.length, 0);
  assert.deepEqual(secretsIn(both.output + neither.output, [token, e.issued.code]), []);
});

test('unknown AGENT_* names, unsupported formats and malformed codes are rejected before any state or network use', async (t) => {
  const e = edge(t); const dir = tmp(t, 'agent-state-');
  for (const [extra, pattern] of [[{ AGENT_DEBUG_SECRET: 'synthetic-value' }, /unknown_env: .*AGENT_DEBUG_SECRET/], [{ AGENT_ENV_FORMAT: '2' }, /unsupported_format/],
    [{ AGENT_BOOTSTRAP: 'fdab_short' }, /bootstrap_malformed/], [{ AGENT_DEPLOYMENT_ID: '../x' }, /deployment_invalid/], [{ AGENT_HOSTNAME: 'Bad Host' }, /hostname_invalid/]]) {
    const run = await start(t, { env: envFor(e.issued, extra), stateDir: dir, request: e.request });
    assert.deepEqual(run.exits, [1]); assert.match(run.output, pattern);
    assert.ok(!run.output.includes('synthetic-value'));
  }
  // Ordinary unrelated environment is allowed; the schema covers every documented agent setting.
  assert.deepEqual(KNOWN_AGENT_ENV, ['AGENT_BOOTSTRAP', 'AGENT_DEPLOYMENT_ID', 'AGENT_ENV_FORMAT', 'AGENT_HOSTNAME', 'AGENT_LOCAL_UPSTREAM', 'AGENT_NAME', 'AGENT_TOKEN']);
  assert.equal(readSettings({ HOME: '/home/node', NODE_VERSION: '20', AGENT_ENV_FORMAT: '1' }).token, undefined);
  assert.deepEqual(fs.readdirSync(dir), []); assert.equal(e.calls.length, 0);
});

test('edge host and audience must be image-pinned HTTPS/WSS on one authority; env cannot add or downgrade one', async (t) => {
  const e = edge(t); const dir = tmp(t, 'agent-state-');
  for (const extra of [{ EDGE_HTTP_URL: 'https://rogue.example.test' }, { EDGE_HTTP_URL: 'http://edge.example.test' }, { EDGE_HTTP_URL: undefined },
    { EDGE_HTTP_URL: 'https://edge.example.test:8443' }, { EDGE_WS_URL: 'wss://rogue.example.test/_fastdog/tunnel' }, { EDGE_WS_URL: 'ws://edge.example.test/_fastdog/tunnel' }]) {
    const run = await start(t, { env: envFor(e.issued, extra), stateDir: dir, request: e.request });
    assert.deepEqual(run.exits, [1], JSON.stringify(extra)); assert.match(run.output, /edge_not_pinned/);
  }
  assert.deepEqual(fs.readdirSync(dir), []); assert.equal(e.calls.length, 0);
  assert.deepEqual(pinnedEdge({ edgeHttpRaw: `${audience}/` }, pins), { audience, http: audience, ws: 'wss://edge.example.test/_fastdog/tunnel' });
  // The shipped pin list is valid; production audiences are added at release review, never via env.
  assert.ok(Array.isArray(loadPins()));
  const bad = path.join(dir, 'pins.json'); fs.writeFileSync(bad, JSON.stringify({ version: 1, audiences: ['http://edge.example.test'] }));
  assert.throws(() => loadPins(bad), /pin list is invalid/);
  fs.rmSync(bad);
  // Only injected loopback fixtures may dial plain HTTP; TLS verification uses the bundled roots and cannot be disabled.
  assert.throws(() => dialTarget('http://edge.example.test/x'), /insecure_edge/);
  assert.throws(() => dialTarget('https://edge.example.test/x', 'http://192.0.2.1:80'), /fixture_not_loopback/);
  assert.equal(dialTarget('https://edge.example.test/_fastdog/tunnel?agentId=a', 'ws://127.0.0.1:9').url.href, 'ws://127.0.0.1:9/_fastdog/tunnel?agentId=a');
  assert.equal(tlsOptions().rejectUnauthorized, true); assert.ok(tlsOptions().ca.length > 0);
});

test('symlinked, wrongly owned/permissioned, unwritable and full volumes abort before any exchange call', async (t) => {
  const e = edge(t);
  const failing = (op, code) => ({ ...fs, constants: fs.constants, [op]: () => { throw Object.assign(new Error(code), { code }); } });
  const cases = [
    ['dir_symlink', (dir) => { const real = tmp(t, 'agent-real-'); fs.rmSync(dir, { recursive: true }); fs.symlinkSync(real, dir); return {}; }, /state_dir_unsafe/],
    ['dir_mode', (dir) => { fs.chmodSync(dir, 0o755); return {}; }, /state_dir_unsafe/],
    ['dir_owner', () => ({ uid: process.getuid() + 1 }), /state_dir_unsafe/],
    ['dir_missing', (dir) => { fs.rmSync(dir, { recursive: true }); return {}; }, /state_dir_missing/],
    ['permission_denied', () => ({ fs: failing('openSync', 'EACCES') }), /state_write_failed/],
    ['disk_full', () => ({ fs: failing('writeSync', 'ENOSPC') }), /state_write_failed/],
    ['fsync_failure', () => ({ fs: failing('fsyncSync', 'EIO') }), /state_write_failed/],
    ['rename_failure', () => ({ fs: failing('renameSync', 'EXDEV') }), /state_write_failed/],
  ];
  for (const [name, prepare, pattern] of cases) {
    const dir = tmp(t, 'agent-state-');
    const extra = prepare(dir);
    const run = await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request, ...extra });
    assert.deepEqual(run.exits, [1], name); assert.match(run.output, pattern, name);
    if (fs.existsSync(dir)) {
      assert.equal(fs.existsSync(stateFile(dir)), false, name);
      assert.deepEqual(fs.readdirSync(dir).filter((n) => n.endsWith('.tmp')), [], `${name}: temp removed`);
    }
  }
  // Failure after the probe but while persisting the pending request also aborts before redemption.
  const dir = tmp(t, 'agent-state-'); let writes = 0;
  const secondWriteFails = { ...fs, constants: fs.constants, renameSync: (...args) => { if (++writes === 2) throw Object.assign(new Error('ENOSPC'), { code: 'ENOSPC' }); return fs.renameSync(...args); } };
  const run = await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request, fs: secondWriteFails });
  assert.deepEqual(run.exits, [1]); assert.equal(fs.existsSync(stateFile(dir)), false);
  assert.equal(e.calls.length, 0);
});

test('pending-key crash recovery: a lost response is recovered with the persisted key; a fresh key gets bootstrap_used and exits', async (t) => {
  const e = edge(t, { faults: ['lost'] }); const dir = tmp(t, 'agent-state-');
  // The edge commits, the response is lost, and the agent crashes before its retry.
  const crashed = await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request, sleep: async () => { throw Object.assign(new Error('crash'), { code: 'crash' }); } });
  assert.deepEqual(crashed.exits, [1]);
  const pending = readState(dir);
  assert.equal(pending.status, 'pending'); assert.equal(pending.attempt, 1);
  // Restart: same key and byte-identical request; the edge returns the identical encrypted response.
  const recovered = await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request, keygen: () => assert.fail('never regenerate a key for a consumed code') });
  assert.deepEqual(recovered.exits, []);
  assert.deepEqual(e.calls[1].body, e.calls[0].body);
  const saved = readState(dir);
  assert.equal(saved.status, 'active'); assert.equal(saved.key_fingerprint, pending.key_fingerprint);
  recovered.result.stop();

  // Leftover env with a fresh, empty volume: a different key is refused; the diagnostic is clear and persisted.
  const fresh = tmp(t, 'agent-state-');
  const used = await start(t, { env: envFor(e.issued), stateDir: fresh, request: e.request, keygen: () => keys[1] });
  assert.deepEqual(used.exits, [1]);
  assert.match(used.output, /bootstrap_used: .*redeemed by a different agent key.*Revoke the agent/);
  assert.equal(readState(fresh).failure, 'bootstrap_used');
  const calls = e.calls.length;
  const restarted = await start(t, { env: envFor(e.issued), stateDir: fresh, request: e.request });
  assert.deepEqual(restarted.exits, [1]); assert.match(restarted.output, /bootstrap_used/);
  assert.equal(e.calls.length, calls, 'a restart after a terminal answer makes no further exchange call');
  assert.deepEqual(secretsIn([crashed.output, recovered.output, used.output].join('\n'), [e.issued.code, saved.token, keys[1].privateKey, e.calls[0].body.proof]), []);
});

test('exchange backoff: 503 and network errors use computeBackoffMs, 429 honours Retry-After, every next attempt is persisted', async (t) => {
  const e = edge(t, { faults: [{ status: 503 }, 'network', { status: 429, headers: { 'retry-after': '7' } }] });
  const dir = tmp(t, 'agent-state-');
  let time = 1_000_000; const waits = [], persisted = [];
  const sleep = async (ms) => { persisted.push(readState(dir).next_attempt_at - time); waits.push(ms); time += ms; };
  const run = await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request, sleep, now: () => time, random: () => 0.5 });
  assert.deepEqual(run.exits, []);
  assert.deepEqual(waits, [500, 1000, 7000]);
  assert.deepEqual(persisted, waits);
  assert.equal(e.calls.length, 4);
  assert.equal(new Set(e.calls.map((c) => JSON.stringify(c.body))).size, 1);
});

test('exchange deadlines: a restart waits for the persisted next attempt; the redeem horizon ends retries without resetting', async (t) => {
  const e = edge(t, { faults: [{ status: 503 }] }); const dir = tmp(t, 'agent-state-');
  let time = 5_000_000;
  const crash = async () => { throw Object.assign(new Error('crash'), { code: 'crash' }); };
  await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request, sleep: crash, now: () => time, random: () => 0.9 });
  const pending = readState(dir);
  assert.equal(pending.deadline_at, 5_000_000 + REDEEM_HORIZON_MS);
  assert.equal(pending.next_attempt_at, time + 900);
  // A restart before the next eligible attempt sleeps first and does not call the edge.
  const waits = [];
  await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request, now: () => time, sleep: async (ms) => { waits.push(ms); throw Object.assign(new Error('crash'), { code: 'crash' }); } });
  assert.deepEqual(waits, [900]); assert.equal(e.calls.length, 1);
  // Past the horizon: no call, terminal expiry is persisted and the deadline is unchanged.
  time = pending.deadline_at;
  const late = await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request, now: () => time });
  assert.deepEqual(late.exits, [1]); assert.match(late.output, /bootstrap_expired/);
  assert.equal(e.calls.length, 1);
  assert.equal(readState(dir).deadline_at, pending.deadline_at);
  // A pending volume restarted with a different code, or with no code, fails closed.
  for (const extra of [{ AGENT_BOOTSTRAP: fakeCode() }, { AGENT_BOOTSTRAP: undefined }]) {
    const other = await start(t, { env: envFor(e.issued, extra), stateDir: dir, request: e.request, now: () => time });
    assert.deepEqual(other.exits, [1]); assert.match(other.output, /state_(binding_mismatch|pending_without_bootstrap)/);
  }
  // Terminal codes from the edge are persisted (no hammering on restart).
  const dir2 = tmp(t, 'agent-state-'); const gone = edge(t, { faults: [{ status: 410 }] });
  const expired = await start(t, { env: envFor(gone.issued), stateDir: dir2, request: gone.request });
  assert.deepEqual(expired.exits, [1]); assert.equal(readState(dir2).failure, 'bootstrap_expired');
});

test('volume lock: a live second writer is refused; a crashed holder\'s lock is reaped; abandoned temps are removed', async (t) => {
  const dir = tmp(t, 'agent-state-');
  const first = await acquireLock(dir, { staleMs: 60000, waitMs: 100 });
  await assert.rejects(acquireLock(dir, { staleMs: 60000, waitMs: 100 }), { code: 'volume_busy' });
  first.release();
  assert.equal(fs.existsSync(path.join(dir, LOCK_FILE)), false);
  // Crash: a lock that is no longer refreshed becomes stale and is recovered.
  fs.writeFileSync(path.join(dir, LOCK_FILE), JSON.stringify({ nonce: 'dead', pid: 1 }), { mode: 0o600 });
  const old = new Date(Date.now() - 120000); fs.utimesSync(path.join(dir, LOCK_FILE), old, old);
  const second = await acquireLock(dir, { staleMs: 60000 });
  assert.equal(second.owned(), true); second.release();
  // An agent that loses its lock is told so.
  let lost = false;
  const third = await acquireLock(dir, { refreshMs: 20, onLost: () => { lost = true; } });
  fs.writeFileSync(path.join(dir, LOCK_FILE), JSON.stringify({ nonce: 'someone-else' }));
  for (let i = 0; i < 200 && !lost; i++) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(lost, true); third.release();
  assert.equal(fs.existsSync(path.join(dir, LOCK_FILE)), true, 'never removes a lock it does not own');
  fs.rmSync(path.join(dir, LOCK_FILE));
  // Startup removes only the agent's own abandoned temp names inside the state directory.
  const e = edge(t);
  const temp = path.join(dir, `.credential.json.${'a'.repeat(32)}.tmp`), keep = path.join(dir, 'unrelated-file');
  fs.writeFileSync(temp, 'partial', { mode: 0o600 }); fs.writeFileSync(keep, 'x', { mode: 0o600 });
  const run = await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request });
  assert.deepEqual(run.exits, []);
  assert.equal(fs.existsSync(temp), false); assert.equal(fs.existsSync(keep), true);
  // Another holder of the volume is refused while it is live.
  const busy = await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request });
  assert.deepEqual(busy.exits, [1]); assert.match(busy.output, /volume_busy/);
});

test('atomicWrite never follows a planted temp symlink and leaves no partial destination', (t) => {
  const dir = tmp(t, 'agent-state-');
  const target = path.join(dir, 'victim'); fs.writeFileSync(target, 'original');
  const realOpen = fs.openSync;
  const planted = { ...fs, constants: fs.constants, openSync: (file, flags, mode) => {
    if (String(file).endsWith('.tmp')) fs.symlinkSync(target, file);
    return realOpen(file, flags, mode);
  } };
  assert.throws(() => atomicWrite(dir, STATE_FILE, 'data', { fs: planted }), { code: 'state_write_failed' });
  assert.equal(fs.readFileSync(target, 'utf8'), 'original');
  assert.equal(fs.existsSync(stateFile(dir)), false);
});

test('key-bound registration: candidate first, then active, then a reconnect-required exit after repeated 401s', async (t) => {
  const e = edge(t); const dir = tmp(t, 'agent-state-');
  const state = activeState(e.issued); writeState(dir, state);
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url, proof: req.headers['x-fastdog-agent-proof'], authorization: req.headers.authorization, host: req.headers.host });
    req.resume(); res.writeHead(401, { 'content-type': 'application/json' }); res.end('{"error":"unauthorized"}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const run = await start(t, { env: envFor(e.issued), stateDir: dir, request: e.request, fixture: { http: `http://127.0.0.1:${server.address().port}` } });
  for (let i = 1; i < MAX_CREDENTIAL_REJECTIONS; i++) await assert.rejects(run.loopFns.registerAgent(), (err) => err.status === 401 && !err.fatal);
  await assert.rejects(run.loopFns.registerAgent(), (err) => err.fatal && err.code === 'credential_rejected');
  assert.deepEqual(seen.map((s) => s.url), Array.from({ length: MAX_CREDENTIAL_REJECTIONS }, () => ['/_fastdog/agents/register?candidate=1', '/_fastdog/agents/register']).flat());
  for (const s of seen) {
    assert.equal(s.authorization, `Bearer ${state.token}`); assert.equal(s.host, 'edge.example.test');
    assert.ok(parseProof([s.proof]));
  }
  assert.equal(new Set(seen.map((s) => s.proof)).size, seen.length, 'every request carries a fresh proof');
  assert.equal(e.calls.length, 0);
});

test('package, lockfile, image label, heartbeat and exchange versions agree and pass the shared validator', () => {
  const manifest = JSON.parse(fs.readFileSync('agent/package.json', 'utf8'));
  const lock = JSON.parse(fs.readFileSync('agent/package-lock.json', 'utf8'));
  const label = /org\.opencontainers\.image\.version=\x22([^\x22]+)\x22/.exec(fs.readFileSync('agent/Dockerfile', 'utf8'))[1];
  assert.equal(AGENT_VERSION, manifest.version);
  assert.equal(lock.version, manifest.version); assert.equal(lock.packages[''].version, manifest.version);
  assert.equal(label, manifest.version);
  assert.equal(validAgentVersion(AGENT_VERSION), true);
  assert.match(AGENT_VERSION, /^\d{1,3}\.\d{1,3}\.\d{1,3}$/);
});

test('the persisted private key signs proofs the persisted fingerprint identifies', () => {
  const der = createPublicKey(createPrivateKey(keys[0].privateKey)).export({ type: 'spki', format: 'der' });
  assert.equal(createHash('sha256').update(der).digest('hex'), keys[0].fingerprint);
  const header = JSON.parse(Buffer.from(proofHeader(keys[0].privateKey, { method: 'GET', target: '/t', audience, credentialId: 'c' }), 'base64url'));
  assert.deepEqual(Object.keys(header), ['v', 'nonce', 'timestamp', 'signature']);
  const transcript = proofTranscript({ method: 'GET', target: '/t', audience, credentialId: 'c', timestamp: header.timestamp, nonce: header.nonce });
  assert.equal(verify('sha256', transcript, { key: createPublicKey(keys[0].publicKey), padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, Buffer.from(header.signature, 'base64url')), true);
});
