// Authenticated issuer check (bootstrap plan sections 4 and 10): the edge client in src/onboard/issuer-check.js against
// the portal listener in portal/src/issuer-check.js over loopback, plus forged replies that must all fail closed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import * as edgeSide from '../src/onboard/issuer-check.js';
import * as portalSide from '../portal/src/issuer-check.js';
import { createIssuerChecker, issuerCheckFromEnv, issuerReplyRejected, MAC_HEADER } from '../src/onboard/issuer-check.js';
import { createBootstrap } from '../src/onboard/bootstrap.js';
import { writeJson } from '../src/onboard/json.js';
import { issueCredential } from '../src/onboard/credentials.js';
import { generateKey, signExchange, sha256 } from '../agent/protocol.js';
import { issuerCheckFixture } from './helpers/issuer-check.js';

const issuer = { kind: 'session', id: 'issuer-1', authorization_generation: 3 };
const secret = () => randomBytes(32).toString('hex');

// Replies built exactly as the portal builds them, so each test changes one thing.
function forge(key, request, overrides = {}, { macKey, mac, now = Date.now() } = {}) {
  const reply = { issuer_kind: request.issuer_kind, issuer_id: request.issuer_id, authorization_generation: request.authorization_generation, nonce: request.nonce, valid: true, checked_at: now, ...overrides };
  const keys = portalSide.issuerCheckKeys(key);
  const header = mac === undefined ? portalSide.issuerMac(macKey ?? keys.reply, portalSide.replyEncoding(reply)) : mac;
  return { status: 200, headers: header === null ? {} : { [MAC_HEADER]: header }, body: Buffer.from(JSON.stringify(reply)) };
}
const rejectedWith = (reason) => ({ status: 503, code: 'bootstrap_unavailable', reason });

test('edge and portal derive the same direction-separated keys and byte-identical encodings', () => {
  const key = secret();
  const request = { issuer_kind: 'api_key', issuer_id: randomUUID(), authorization_generation: 2, nonce: randomBytes(32).toString('base64url') };
  const reply = { ...request, valid: false, checked_at: 1234567890123 };
  const edgeKeys = edgeSide.issuerCheckKeys(key), portalKeys = portalSide.issuerCheckKeys(key);
  assert.deepEqual(edgeKeys, portalKeys);
  assert.notDeepEqual(edgeKeys.request, edgeKeys.reply);
  assert.deepEqual(edgeSide.requestEncoding(request), portalSide.requestEncoding(request));
  assert.deepEqual(edgeSide.replyEncoding(reply), portalSide.replyEncoding(reply));
  assert.notDeepEqual(edgeSide.requestEncoding(request), edgeSide.replyEncoding({ ...request, valid: false, checked_at: 0 }));
  // Generation type is part of the encoding: 2 and "2" never collide.
  assert.notDeepEqual(edgeSide.requestEncoding(request), edgeSide.requestEncoding({ ...request, authorization_generation: '2' }));
  assert.equal(edgeSide.ISSUER_CHECK_PATH, portalSide.ISSUER_CHECK_PATH);
  assert.equal(edgeSide.MAC_HEADER, portalSide.MAC_HEADER);
});

test('a real portal listener answers valid and invalid issuers; the edge accepts only its authenticated reply', async (t) => {
  const listener = await issuerCheckFixture(t, { validate: (i) => i.issuer_id === 'issuer-1' });
  const { check } = createIssuerChecker({ url: listener.url, secret: listener.secret });
  assert.equal(await check(issuer), true);
  assert.equal(await check({ ...issuer, id: 'someone-else' }), false);
  assert.deepEqual(listener.seen.map((s) => Object.keys(s).sort()), [0, 1].map(() => ['authorization_generation', 'issuer_id', 'issuer_kind', 'nonce']));
  // A key from another environment: the listener refuses it, the edge reports unavailable.
  const other = createIssuerChecker({ url: listener.url, secret: secret() });
  await assert.rejects(other.check(issuer), rejectedWith('status'));
  assert.equal(listener.seen.length, 2);
});

test('forged, replayed, mismatched, stale or misdirected replies are 503 and never valid', () => {
  const key = secret(); let time = 1_800_000_000_000;
  const checker = createIssuerChecker({ url: 'http://127.0.0.1:1/internal/v1/issuer-check', secret: key, now: () => time });
  const before = issuerReplyRejected();
  const cases = [
    ['missing_mac', (r) => forge(key, r, {}, { mac: null })],
    ['invalid_mac', (r) => forge(key, r, {}, { mac: randomBytes(32).toString('base64url') })],
    // The request-direction MAC (as the edge sent it), and a reply MAC computed with the request key, never verify as replies.
    ['invalid_mac', (r) => forge(key, r, {}, { mac: portalSide.issuerMac(portalSide.issuerCheckKeys(key).request, portalSide.requestEncoding(r)) })],
    ['invalid_mac', (r) => forge(key, r, {}, { macKey: portalSide.issuerCheckKeys(key).request })],
    ['invalid_mac', (r) => forge(secret(), r)],
    ['mismatch', (r) => forge(key, r, { issuer_id: 'issuer-2' })],
    ['mismatch', (r) => forge(key, r, { authorization_generation: 4 })],
    ['mismatch', (r) => forge(key, r, { authorization_generation: '3' })],
    ['unknown_nonce', (r) => forge(key, r, { nonce: randomBytes(32).toString('base64url') })],
    ['stale', (r) => forge(key, r, {}, { now: time - 5001 })],
    ['stale', (r) => forge(key, r, {}, { now: time + 5001 })],
    ['malformed', (r) => ({ ...forge(key, r), body: Buffer.from('{') })],
    ['malformed', (r) => forge(key, r, { valid: 'true' })],
    ['malformed', (r) => forge(key, r, { extra: 1 })],
    ['status', (r) => ({ ...forge(key, r), status: 500 })],
    ['rate_limited', (r) => ({ ...forge(key, r), status: 429 })],
  ];
  for (const [reason, build] of cases) {
    const request = checker.begin(issuer);
    assert.throws(() => checker.accept(request, build(request)), rejectedWith(reason), reason);
  }
  // Valid once; the same reply again is a reused nonce.
  const request = checker.begin(issuer); const reply = forge(key, request, {}, { now: time });
  assert.equal(checker.accept(request, reply), true);
  assert.throws(() => checker.accept(request, reply), rejectedWith('reused_nonce'));
  // A valid reply for a different outstanding request is refused and leaves that request answerable.
  const a = checker.begin(issuer), b = checker.begin(issuer);
  const forA = forge(key, a, {}, { now: time });
  assert.throws(() => checker.accept(b, forA), rejectedWith('different_request'));
  assert.equal(checker.accept(a, forA), true);
  // A reply arriving after the 5 s window: expired nonce, even though checked_at is fresh.
  const late = checker.begin(issuer); time += 5001;
  assert.throws(() => checker.accept(late, forge(key, late, {}, { now: time })), rejectedWith('expired_nonce'));
  // The authenticated false is accepted as false (not an error), and it is never true.
  const no = checker.begin(issuer);
  assert.equal(checker.accept(no, forge(key, no, { valid: false }, { now: time })), false);
  const after = issuerReplyRejected();
  for (const reason of ['missing_mac', 'mismatch', 'unknown_nonce', 'stale', 'malformed', 'status', 'rate_limited', 'reused_nonce', 'different_request', 'expired_nonce']) {
    assert.ok(after[reason] > before[reason], reason);
  }
  assert.equal(after.invalid_mac - before.invalid_mac, 4);
  assert.deepEqual(Object.keys(after), [...edgeSide.REJECT_REASONS]);
});

test('the outstanding-nonce table is bounded and fails closed at capacity', () => {
  let time = 0;
  const checker = createIssuerChecker({ url: 'http://127.0.0.1:1/internal/v1/issuer-check', secret: secret(), now: () => time, capacity: 2 });
  checker.begin(issuer); checker.begin(issuer);
  assert.throws(() => checker.begin(issuer), rejectedWith('capacity'));
  time += 10001;
  assert.ok(checker.begin(issuer).nonce);
});

function exchangeFixture(t, issuerCheck) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'issuer-exchange-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const tid = 't_aaaaaaaaaaaaaaaaaaaa', hostname = 'app.example.test', audience = 'https://edge.example.test', origin = 'http://127.0.0.1:8080';
  const active = issueCredential({ tenant_id: tid, hostname }, directory);
  writeJson('tenant_hostnames.json', [{ tenant_id: tid, hostname, status: 'active', txt_value: randomBytes(8).toString('hex'), verified_at: new Date().toISOString(), created_at: new Date().toISOString(), credential_id: active.id }], 0o600, directory);
  const service = createBootstrap({ bootstrapEnabled: true, bootstrapAudience: audience, dataDir: directory, issuerCheck });
  t.after(() => service.close());
  const issued = service.issue(tid, hostname, { origin, deployment_id: randomUUID(), issuance_id: randomUUID(), issuer });
  const key = generateKey();
  const body = { hostname, origin, deployment_id: issued.deployment_id, request_id: randomUUID(), recipient_public_key: key.publicKey, agent_version: '1.2.3' };
  body.proof = signExchange(key.privateKey, audience, sha256(issued.code), body);
  return { service, issued, body };
}

test('exchange: every rejected reply is a retryable 503 that consumes nothing; only an authenticated true redeems', async (t) => {
  const key = secret();
  let respond;
  const checker = createIssuerChecker({ url: 'http://127.0.0.1:1/internal/v1/issuer-check', secret: key, transport: async (_url, raw) => respond(JSON.parse(raw)) });
  const f = exchangeFixture(t, checker.check);
  for (const bad of [(r) => forge(key, r, {}, { mac: null }), (r) => forge(key, r, { issuer_id: 'x' }), (r) => forge(key, r, {}, { now: Date.now() - 6000 }),
    (r) => forge(key, r, {}, { macKey: portalSide.issuerCheckKeys(key).request }), (r) => forge(key, { ...r, nonce: randomBytes(32).toString('base64url') })]) {
    respond = bad;
    await assert.rejects(f.service.exchange(f.issued.code, f.body, '127.0.0.1'), { status: 503, code: 'bootstrap_unavailable' });
  }
  respond = () => { throw new Error('connection refused'); };
  await assert.rejects(f.service.exchange(f.issued.code, f.body, '127.0.0.1'), { status: 503 });
  respond = (r) => forge(key, r, { valid: false });
  await assert.rejects(f.service.exchange(f.issued.code, f.body, '127.0.0.1'), { status: 401, code: 'unauthorized' });
  respond = (r) => forge(key, r);
  const result = await f.service.exchange(f.issued.code, f.body, '127.0.0.1');
  assert.equal(result.hostname, 'app.example.test');
});

test('unconfigured issuer check fails closed; partial or reused configuration fails enabled startup without echoing values', (t) => {
  const saved = { ...process.env };
  t.after(() => { for (const k of ['AGENT_BOOTSTRAP_ISSUER_CHECK_URL', 'AGENT_BOOTSTRAP_ISSUER_CHECK_KEY', 'PORTAL_KEY']) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });
  assert.equal(issuerCheckFromEnv({}), undefined);
  const key = secret(), url = 'http://127.0.0.1:8792/internal/v1/issuer-check';
  for (const env of [{ AGENT_BOOTSTRAP_ISSUER_CHECK_URL: url }, { AGENT_BOOTSTRAP_ISSUER_CHECK_KEY: key }, { AGENT_BOOTSTRAP_ISSUER_CHECK_URL: url, AGENT_BOOTSTRAP_ISSUER_CHECK_KEY: 'short' },
    { AGENT_BOOTSTRAP_ISSUER_CHECK_URL: url, AGENT_BOOTSTRAP_ISSUER_CHECK_KEY: key, PORTAL_KEY: key }, { AGENT_BOOTSTRAP_ISSUER_CHECK_URL: url, AGENT_BOOTSTRAP_ISSUER_CHECK_KEY: key, AGENT_TOKEN: key },
    { AGENT_BOOTSTRAP_ISSUER_CHECK_URL: 'http://192.0.2.1:8792/internal/v1/issuer-check', AGENT_BOOTSTRAP_ISSUER_CHECK_KEY: key },
    { AGENT_BOOTSTRAP_ISSUER_CHECK_URL: 'https://127.0.0.1:8792/internal/v1/issuer-check', AGENT_BOOTSTRAP_ISSUER_CHECK_KEY: key },
    { AGENT_BOOTSTRAP_ISSUER_CHECK_URL: 'http://127.0.0.1:8792/other', AGENT_BOOTSTRAP_ISSUER_CHECK_KEY: key }]) {
    assert.throws(() => issuerCheckFromEnv(env), (e) => !e.message.includes(key) && /issuer[ _]check/i.test(e.message), JSON.stringify(Object.keys(env)));
  }
  assert.equal(typeof issuerCheckFromEnv({ AGENT_BOOTSTRAP_ISSUER_CHECK_URL: url, AGENT_BOOTSTRAP_ISSUER_CHECK_KEY: key }), 'function');
  // Enabled bootstrap with nothing configured: exchange is 503, never permissive.
  delete process.env.AGENT_BOOTSTRAP_ISSUER_CHECK_URL; delete process.env.AGENT_BOOTSTRAP_ISSUER_CHECK_KEY;
  const f = exchangeFixture(t, undefined);
  assert.equal(f.service.issuerCheck, undefined);
  return assert.rejects(f.service.exchange(f.issued.code, f.body, '127.0.0.1'), { status: 503 });
});
