import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { readJson, writeJson } from '../src/onboard/json.js';
import { validCredential, issueCredential, LAST_USED_WRITE_INTERVAL } from '../src/onboard/credentials.js';
import { createClaims } from '../src/internal/claims.js';

const tid = 't_aaaaaaaaaaaaaaaaaaaa';
const other = 't_bbbbbbbbbbbbbbbbbbbb';
const host = 'app.example.test';

function tempDir(t) {
  const directory = fs.mkdtempSync(path.join(process.cwd(), 'test/.robust-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// writeJson replaces the file by rename, so every persisted write yields a new inode.
const inode = (directory) => fs.statSync(path.join(directory, 'agent-credentials.json')).ino;
const lastUsed = (directory) => readJson('agent-credentials.json', [], directory)[0].last_used_at;

test('validCredential persists last_used_at at most once per credential per minute', (t) => {
  const directory = tempDir(t);
  let time = Date.UTC(2026, 0, 1);
  const now = () => time;
  const { token } = issueCredential({ hostname: host }, directory, now);
  const second = issueCredential({ hostname: 'other.example.test' }, directory, now);
  assert.equal(validCredential(token, host, directory, now), true);
  assert.equal(lastUsed(directory), new Date(time).toISOString());
  const first = inode(directory);
  for (let i = 0; i < 5; i++) {
    time += 10000;
    assert.equal(validCredential(token, host, directory, now), true);
  }
  assert.equal(inode(directory), first);
  assert.equal(lastUsed(directory), new Date(Date.UTC(2026, 0, 1)).toISOString());
  // Throttling is per credential: another credential's first use still persists.
  assert.equal(validCredential(second.token, 'other.example.test', directory, now), true);
  assert.notEqual(inode(directory), first);
  time = Date.UTC(2026, 0, 1) + LAST_USED_WRITE_INTERVAL;
  const before = inode(directory);
  assert.equal(validCredential(token, host, directory, now), true);
  assert.notEqual(inode(directory), before);
  assert.equal(lastUsed(directory), new Date(time).toISOString());
  // Wrong token or host is still refused regardless of throttling.
  assert.equal(validCredential(token, 'other.example.test', directory, now), false);
  assert.equal(validCredential('0'.repeat(64), host, directory, now), false);
});

test('revocation is immediate even inside the throttle window', (t) => {
  const directory = tempDir(t);
  const time = Date.UTC(2026, 0, 1);
  const now = () => time;
  const { token } = issueCredential({ hostname: host }, directory, now);
  assert.equal(validCredential(token, host, directory, now), true);
  const credentials = readJson('agent-credentials.json', [], directory);
  credentials[0].revoked_at = new Date(time).toISOString();
  writeJson('agent-credentials.json', credentials, 0o600, directory);
  assert.equal(validCredential(token, host, directory, now), false);
  assert.equal(readJson('agent-credentials.json', [], directory)[0].revoked_at, new Date(time).toISOString());
});

function claimsFixture(t, extra = {}) {
  let time = Date.UTC(2026, 0, 1);
  const claims = createClaims({ dataDir: tempDir(t), attachTarget: 'attach.example-edge.test', altAttachTarget: 'edge.example.test',
    edgePublicIp: '192.0.2.1', reservedSuffixes: [], resolver: {}, now: () => time, ...extra }, () => {});
  const create = (tenant, name) => {
    try { return claims.create(tenant, { hostname: name, hostname_limit: 1000 }); } catch (error) { return error; }
  };
  return { claims, create, advance(ms) { time += ms; } };
}

test('claim create rate limit is off by default', (t) => {
  const f = claimsFixture(t);
  for (let i = 0; i < 30; i++) assert.equal(f.create(tid, `a${i}.example.com`).status, 201);
});

test('CLAIM_CREATE_RATE_LIMIT limits creates per tenant per minute with retry_after', (t) => {
  for (const value of ['0', 'abc', '-1', '1.5']) {
    const f = claimsFixture(t, { claimCreateRateLimit: value });
    for (let i = 0; i < 5; i++) assert.equal(f.create(tid, `a${i}.example.com`).status, 201);
  }
  const f = claimsFixture(t, { claimCreateRateLimit: '3' });
  for (let i = 0; i < 3; i++) assert.equal(f.create(tid, `a${i}.example.com`).status, 201);
  f.advance(15000);
  const limited = f.create(tid, 'a3.example.com');
  assert.equal(limited.status, 429);
  assert.equal(limited.code, 'rate_limited');
  assert.equal(limited.retry_after, 45);
  assert.equal(f.create(other, 'b0.example.com').status, 201);
  f.advance(45000);
  assert.equal(f.create(tid, 'a3.example.com').status, 201);
});

test('claim create limiter memory is bounded', (t) => {
  const f = claimsFixture(t, { claimCreateRateLimit: 1 });
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  const tenant = (i) => `t_${[...i.toString(32).padStart(20, '0')].map((d) => alphabet[parseInt(d, 32)]).join('')}`;
  // Invalid bodies still count as create attempts and never touch disk.
  for (let i = 0; i <= 10000; i++) assert.equal(f.create(tenant(i), '').code, 'invalid_hostname');
  assert.equal(f.create(tenant(10000), '').code, 'rate_limited');
  // The oldest window was evicted to keep at most 10000 tenants in memory.
  assert.equal(f.create(tenant(0), '').code, 'invalid_hostname');
});
