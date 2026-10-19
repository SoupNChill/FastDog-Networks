import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { chargeReissue } from '../src/onboard/bootstrap-budget.js';
import { createBootstrap } from '../src/onboard/bootstrap.js';
import { readJson, writeJson, authTransaction } from '../src/onboard/json.js';
const tid = 't_aaaaaaaaaaaaaaaaaaaa', host = 'app.example.test';
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refund-'));
  let time = 20000 * 86400000;
  writeJson('tenant_hostnames.json', [host, 'other.example.test'].map(hostname => ({ tenant_id: tid, hostname, status: 'active', created_at: 'generation', credential_id: 'active' })), 0o600, dir);
  const opts = { bootstrapEnabled: true, dataDir: dir, bootstrapAudience: 'https://edge.example.test', now: () => time };
  const service = createBootstrap(opts);
  t.after(() => { service.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const issue = (hostname = host, id = randomUUID(), kind = 'session') => service.issue(tid, hostname, { issuance_id: id, deployment_id: randomUUID(), origin: 'http://127.0.0.1:8080', issuer: { kind, id: 'principal', authorization_generation: 1 } });
  const state = () => readJson('agent-bootstrap.json', {}, dir);
  return { dir, opts, service, issue, state, advance: ms => time += ms, refund: id => service.reconcile(tid, host, id) };
}
test('orphan expiry/refund is durable, scoped and idempotent; no code or digest is returned', t => {
  const f = fixture(t), issued = f.issue();
  assert.equal(f.refund(issued.issuance_id).refunded, false);
  f.advance(900000);
  const result = f.refund(issued.issuance_id);
  assert.equal(result.refunded_units, 1);
  const restarted = createBootstrap(f.opts); t.after(() => restarted.close());
  assert.deepEqual(restarted.reconcile(tid, host, issued.issuance_id), result);
  assert.equal(f.state().budgets[host].rotations, 0);
  assert.equal(f.state().budgets[host].issuances, 1);
  for (const id of [issued.code, f.state().codes[0].code_hash]) assert.ok(!JSON.stringify(result).includes(id));
  for (const id of [issued.issuance_id, 'unknown']) assert.throws(() => f.service.reconcile(tid, 'other.example.test', id), { status: 404, code: 'bootstrap_not_found' });
});
test('three refunds per hostname/day, across issuer types; eight committed issuances absolute', t => {
  const f = fixture(t);
  for (let i = 0; i < 8; i++) {
    const issued = f.issue(host, randomUUID(), ['session', 'api_key', 'connect_token'][i % 3]); f.advance(900000);
    assert.equal(f.refund(issued.issuance_id).refunded, i < 3);
  }
  assert.equal(f.state().budgets[host].rotations, 5);
  assert.equal(f.state().budgets[host].issuances, 8);
  assert.throws(() => f.issue(), { status: 429 });
  authTransaction(f.dir, () => { const s = f.state(); s.budgets[host].rotations = 0; writeJson('agent-bootstrap.json', s, 0o600, f.dir); });
  assert.throws(() => f.issue(), { status: 429 }); // independently enforce the absolute ceiling
});
test('revocation permits refund, redeemed and uncertain records do not; rollover never credits new window', t => {
  const f = fixture(t), a = f.issue(); f.service.cancel(tid, host);
  assert.equal(f.refund(a.issuance_id).refunded, true);
  const b = f.issue(); f.service.cancel(tid, host);
  authTransaction(f.dir, () => { const s = f.state(); s.codes.at(-1).redeemed_at = f.opts.now(); writeJson('agent-bootstrap.json', s, 0o600, f.dir); });
  assert.equal(f.refund(b.issuance_id).refunded, false);
  const c = f.issue(); f.service.cancel(tid, host);
  authTransaction(f.dir, () => { const s = f.state(); delete s.codes.at(-1).charge; writeJson('agent-bootstrap.json', s, 0o600, f.dir); });
  assert.equal(f.refund(c.issuance_id).refunded, false);
  const d = f.issue(); f.advance(86400000);
  assert.equal(f.refund(d.issuance_id).refunded, false);
  assert.throws(() => f.refund('unknown'), { status: 404 });
});
test('cancel-by-reissue limits span hostnames and reject before even expiry maintenance writes', t => {
  const f = fixture(t); f.issue(); f.issue('other.example.test');
  f.issue(); f.issue('other.example.test'); f.issue();
  const file = path.join(f.dir, 'agent-auth-state.json'), before = fs.readFileSync(file, 'utf8');
  assert.throws(() => f.issue('other.example.test'), { status: 429 });
  assert.equal(fs.readFileSync(file, 'utf8'), before);
});
test('failed snapshot commit and retry never double refund', t => {
  const f = fixture(t), a = f.issue(); f.advance(900000);
  const rename = fs.renameSync;
  fs.renameSync = () => { throw new Error('synthetic persistence failure'); };
  try { assert.throws(() => f.refund(a.issuance_id)); } finally { fs.renameSync = rename; }
  assert.equal(f.state().budgets[host].rotations, 1);
  assert.equal(f.refund(a.issuance_id).refunded, true);
  assert.equal(f.refund(a.issuance_id).refunded, true);
  assert.equal(f.state().budgets[host].rotations, 0);
});
test('interleaved independent services serialize issue and reconciliation without lost counters', async t => {
  const f = fixture(t), a = f.issue(); f.advance(900000);
  const second = createBootstrap(f.opts); t.after(() => second.close());
  await Promise.all([Promise.resolve().then(() => f.refund(a.issuance_id)), Promise.resolve().then(() => f.issue()), Promise.resolve().then(() => second.reconcile(tid, host, a.issuance_id))]);
  assert.equal(f.state().budgets[host].rotations, 1);
  assert.equal(f.state().budgets[host].issuances, 2);
});

test('principal UTC-day reissue cap survives hourly windows and issuer generation changes', () => {
  const state = { codes: [{ tenant_id: tid, hostname: host, expires_at: 86400000 }] };
  const issuer = { kind: 'session', id: 'principal' };
  for (let hour = 0; hour < 2; hour++) for (let i = 0; i < 3; i++) chargeReissue(state, tid, host, { ...issuer, authorization_generation: i }, hour * 3600000);
  assert.throws(() => chargeReissue(state, tid, host, issuer, 7200000), { status: 429 });
});
test('post-rename uncertain acknowledgement retries from committed refund marker', t => {
  const f = fixture(t), a = f.issue(); f.advance(900000);
  const rename = fs.renameSync;
  fs.renameSync = (...args) => { rename(...args); throw new Error('synthetic lost acknowledgement'); };
  try { assert.throws(() => f.refund(a.issuance_id)); } finally { fs.renameSync = rename; }
  assert.equal(f.refund(a.issuance_id).refunded_units, 1);
  assert.equal(f.state().budgets[host].rotations, 0);
  assert.equal(f.state().budgets[host].refunds, 1);
});
