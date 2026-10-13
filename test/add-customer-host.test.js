import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { ENFORCE_DENYLIST } from '../verdict/src/config/hosts.js';
const script = resolve('scripts/add-customer-host.sh');
function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'add-host-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'Caddyfile');
  const initial = '(fdlog) {}\nexisting.example.test {\n reverse_proxy localhost:8787\n}\n';
  writeFileSync(file, initial);
  for (const name of ['caddy', 'systemctl']) writeFileSync(join(dir, name), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${dir}/calls'\nexit "\${${name === 'caddy' ? 'VALIDATE_STATUS' : 'RELOAD_STATUS'}:-0}"\n`, { mode: 0o755 });
  // Exercise write logic without privileged access: only the fixture copy's UID check
  // and checkout location change. The original script's root refusal is tested below.
  const fixtureScript = join(dir, 'add-host.sh');
  writeFileSync(fixtureScript, readFileSync(script, 'utf8')
    .replace('[[ $EUID == 0 ]]', '[[ 0 == 0 ]]')
    .replace(/^repo=.*$/m, `repo='${resolve('.').replaceAll("'", "'\\''")}'`));
  const run = (args, extra = {}) => spawnSync('bash', [fixtureScript, ...args], { encoding: 'utf8', env: { ...process.env, CADDYFILE: file, BIN: dir, ...extra } });
  return { dir, file, initial, run };
}
test('add host rejects all canonical guardrails and their subdomains', t => {
  const f = fixture(t);
  for (const host of [...ENFORCE_DENYLIST, ...ENFORCE_DENYLIST.map(host => `child.${host}`), ['lease', 'example', 'test'].join('.')]) {
    const result = f.run(['--dry-run', host]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /protected hostname/);
  }
});
test('add host strictly validates names and detects existing names case-insensitively', t => {
  const f = fixture(t);
  for (const host of ['-bad.example.test', 'bad..test', 'example.test/path', 'example.test.', '*.example.test', 'a;id.example.test', `${'a'.repeat(64)}.test`, '127.0.0.1']) assert.notEqual(f.run(['--dry-run', host]).status, 0);
  assert.match(f.run(['--dry-run', 'EXISTING.EXAMPLE.TEST']).stderr, /already present/);
  writeFileSync(f.file, 'https://app.example.test:443, other.example.test {\n}\n');
  assert.match(f.run(['--dry-run', 'app.example.test']).stderr, /already present/);
});
test('dry run prints the attached-host pattern and changes nothing', t => {
  const f = fixture(t); const before = readdirSync(f.dir);
  const result = f.run(['--dry-run', 'APP.EXAMPLE.TEST']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'app.example.test {\n    import fdlog app.example.test\n    reverse_proxy localhost:8787\n}\n');
  assert.equal(readFileSync(f.file, 'utf8'), f.initial);
  assert.deepEqual(readdirSync(f.dir), before);
});
test('successful writes back up, validate, reload and print rollback', t => {
  const f = fixture(t); const result = f.run(['app.example.test']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Rollback: cp -p/);
  const backup = readdirSync(f.dir).find(name => name.startsWith('Caddyfile.bak-addhost-app.example.test-'));
  assert.equal(readFileSync(join(f.dir, backup), 'utf8'), f.initial);
  assert.match(readFileSync(f.file, 'utf8'), /import fdlog app.example.test/);
  assert.equal(readFileSync(join(f.dir, 'calls'), 'utf8'), `validate --config ${f.file} --adapter caddyfile\nreload caddy\n`);
});
test('validation and reload failures restore the original file', t => {
  for (const variable of ['VALIDATE_STATUS', 'RELOAD_STATUS']) {
    const f = fixture(t); const result = f.run(['app.example.test'], { [variable]: '1' });
    assert.notEqual(result.status, 0);
    assert.equal(readFileSync(f.file, 'utf8'), f.initial);
    if (variable === 'VALIDATE_STATUS') assert.doesNotMatch(readFileSync(join(f.dir, 'calls'), 'utf8'), /reload/);
  }
});

test('original script requires root for writes', t => {
  const f = fixture(t);
  if (process.getuid() === 0) return assert.match(readFileSync(script, 'utf8'), /\[\[ \$EUID == 0 \]\]/);
  const result = spawnSync('bash', [script, 'app.example.test'], { encoding: 'utf8', env: { ...process.env, CADDYFILE: f.file, BIN: f.dir } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Run as root/);
  assert.equal(readFileSync(f.file, 'utf8'), f.initial);
});
