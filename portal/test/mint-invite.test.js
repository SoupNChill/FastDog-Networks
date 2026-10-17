import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { temporary, fakeSecret } from './helpers.js';
import { digest } from '../src/tokens.js';

const cli = fileURLToPath(new URL('../bin/mint-invite.js', import.meta.url));
const run = (args, env) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8',
  env: { PATH: process.env.PATH, NODE_OPTIONS: process.env.NODE_OPTIONS || '', ...env } });
const invites = (dir) => JSON.parse(readFileSync(join(dir, 'accounts.json'), 'utf8')).invites;

test('mint-invite prints the code by default and sends nothing', (t) => {
  const dir = temporary(t);
  const result = run(['new@example.test'], { STATE_DIRECTORY: dir });
  assert.equal(result.status, 0, result.stderr);
  const code = result.stdout.trim();
  assert.equal(invites(dir)[0].code_hash, digest(code));
  assert.ok(!existsSync(join(dir, 'outbox')));
});

test('mint-invite --send mails the code through the configured transport without printing it', (t) => {
  const dir = temporary(t);
  const result = run(['--send', 'New@Example.test', 'trial', '1'], { STATE_DIRECTORY: dir, PORTAL_ORIGIN: 'https://portal.example.test' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { delivered: 'outbox' });
  const [file] = readdirSync(join(dir, 'outbox'));
  const message = JSON.parse(readFileSync(join(dir, 'outbox', file), 'utf8'));
  assert.deepEqual({ ...message, code: undefined }, { to: 'new@example.test', kind: 'invite', link: 'https://portal.example.test/signup', code: undefined });
  assert.equal(invites(dir)[0].code_hash, digest(message.code));
  assert.ok(!result.stdout.includes(message.code) && !result.stderr.includes(message.code));
});

test('mint-invite --send with invalid mail settings fails generically and mints nothing', (t) => {
  const dir = temporary(t);
  const pass = fakeSecret();
  for (const env of [{ MAIL_TRANSPORT: 'smtp', SMTP_PASS: pass, PORTAL_ORIGIN: 'https://portal.example.test' }, { MAIL_TRANSPORT: 'file' }]) {
    const result = run(['--send', 'new@example.test'], { STATE_DIRECTORY: dir, ...env });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /^Usage:/);
    assert.ok(!result.stderr.includes(pass) && !result.stdout.includes(pass));
  }
  assert.ok(!existsSync(join(dir, 'accounts.json')));
});
