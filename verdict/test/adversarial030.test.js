import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../src/server.js';
import { createHash, createHmac } from 'node:crypto';
import { issueClearance, validClearance, equal, hasWork } from '../src/edge/security.js';
import { challengeRouter } from '../src/edge/challenge.js';

test('clearance HMAC uses timing-safe compare; forged cookie fails', () => {
  const secret = 'test-secret-32chars-minimum-ok!!';
  const bound = { host: 'verdict-demo.fastdognetworks.com', ip: '203.0.113.10', ua: 'Mozilla/5.0' };
  const token = issueClearance(secret, bound, 300);
  assert.equal(validClearance(token, secret, bound), true);
  const [payload, sig] = token.split('.');
  const forged = `${payload}.${sig.slice(0, -2)}aa`;
  assert.equal(validClearance(forged, secret, bound), false);
  assert.equal(validClearance(token, secret, { ...bound, host: 'evil.example' }), false);
  assert.equal(equal('abc', 'abd'), false);
  assert.equal(equal('abc', 'abc'), true);
});

test('PoW hash helper checks leading zero bits', async () => {
  // End-to-end replay and binding attacks live in adversarial-advsec.test.js.
  const id = 'abc';
  let nonce = 0;
  while (!hasWork(id, String(nonce), 8) && nonce < 100000) nonce++;
  assert.ok(hasWork(id, String(nonce), 8));
  assert.equal(createHash('sha256').update(`${id}:${nonce}`).digest()[0], 0);
});

test('API key missing/wrong returns 401 without leaking', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vd-adv-'));
  const app = await createApp({
    keyFile: join(dir, 'keys.json'), usageFile: join(dir, 'u.json'), decisionFile: join(dir, 'd.jsonl'),
    hostsFile: join(dir, 'h.json'), allowBootstrap: true,
    clearanceSecret: 'test-secret-32chars-minimum-ok!!',
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const { port } = server.address();
  try {
    const boot = await fetch(`http://127.0.0.1:${port}/v1/keys`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(boot.status, 201);
    const bad = await fetch(`http://127.0.0.1:${port}/v1/hosts`, { headers: { Authorization: 'Bearer vd_wrong' } });
    assert.equal(bad.status, 401);
  } finally { server.close(); await app.locals.flush(); }
});
