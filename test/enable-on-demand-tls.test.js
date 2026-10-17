import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const script = resolve('deploy/caddy/enable-on-demand-tls.sh');
const initial = '(fdlog) {}\n(fdctl) {\n    @ctl path /_fastdog/*\n}\nexisting.example.test {\n    import fdlog existing.example.test\n    reverse_proxy 127.0.0.1:8787\n}\n';
const globalBlock = '{\n    on_demand_tls {\n        ask http://127.0.0.1:8789/tls/ask\n    }\n}\n';
const siteBlock = 'https:// {\n    tls {\n        on_demand\n    }\n    import fdctl\n    reverse_proxy 127.0.0.1:8787\n}\n';

function fixture(t, content = initial) {
  const dir = mkdtempSync(join(tmpdir(), 'on-demand-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, 'bin');
  const etc = join(dir, 'etc');
  mkdirSync(bin);
  mkdirSync(etc);
  const file = join(etc, 'Caddyfile');
  const calls = join(dir, 'calls');
  writeFileSync(file, content);
  // The fake caddy snapshots the candidate it was asked to validate.
  writeFileSync(join(bin, 'caddy'), `#!/bin/sh
printf 'caddy %s\\n' "$*" >> '${calls}'
if [ "$1" = validate ]; then
  while [ $# -gt 0 ]; do [ "$1" = --config ] && cp "$2" '${dir}/validated'; shift; done
fi
exit "\${VALIDATE_STATUS:-0}"
`, { mode: 0o755 });
  writeFileSync(join(bin, 'systemctl'), `#!/bin/sh
printf 'systemctl %s\\n' "$*" >> '${calls}'
case "$1" in
  reload) exit "\${RELOAD_STATUS:-0}" ;;
  is-active) exit "\${ACTIVE_STATUS:-0}" ;;
esac
`, { mode: 0o755 });
  // Only the fixture copy's UID check changes; the original's root refusal is tested separately.
  const fixtureScript = join(dir, 'enable.sh');
  writeFileSync(fixtureScript, readFileSync(script, 'utf8').replace('[[ $EUID == 0 ]]', '[[ 0 == 0 ]]'));
  const run = (args = [], extra = {}) => spawnSync('bash', [fixtureScript, ...args],
    { encoding: 'utf8', env: { ...process.env, BIN: bin, ...extra } });
  const callLog = () => (existsSync(calls) ? readFileSync(calls, 'utf8').trim().split('\n') : []);
  const backups = () => readdirSync(etc).filter((name) => name.startsWith('Caddyfile.bak-ondemand-') && !name.includes('prerollback'));
  return { dir, etc, file, run, callLog, backups, read: () => readFileSync(file, 'utf8') };
}

test('dry run prints the candidate diff and writes nothing', (t) => {
  const f = fixture(t);
  const before = readdirSync(f.etc);
  const result = f.run(['--dry-run', f.file]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /^\+\s+on_demand_tls \{$/m);
  assert.match(result.stdout, /^\+\s+ask http:\/\/127\.0\.0\.1:8789\/tls\/ask$/m);
  assert.match(result.stdout, /^\+https:\/\/ \{$/m);
  assert.match(result.stdout, /^\+\s+import fdctl$/m);
  assert.equal(f.read(), initial);
  assert.deepEqual(readdirSync(f.etc), before);
  assert.deepEqual(f.callLog(), []);
});

test('enable prepends the global block, appends the catch-all and leaves existing sites byte-identical', (t) => {
  const f = fixture(t);
  const result = f.run([f.file]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.read(), `${globalBlock}\n${initial}\n${siteBlock}`);
  assert.ok(f.read().includes(initial), 'existing blocks are untouched');
  const [backup] = f.backups();
  assert.equal(f.backups().length, 1);
  assert.equal(readFileSync(join(f.etc, backup), 'utf8'), initial);
  assert.match(result.stdout, new RegExp(`--rollback .*${backup}`));
  // The validated candidate is the exact installed content, and validation precedes reload.
  assert.equal(readFileSync(join(f.dir, 'validated'), 'utf8'), f.read());
  const calls = f.callLog();
  assert.match(calls[0], /^caddy validate --adapter caddyfile --config .*Caddyfile\.candidate-ondemand-/);
  assert.deepEqual(calls.slice(1), ['systemctl reload caddy', 'systemctl is-active --quiet caddy']);
  assert.deepEqual(readdirSync(f.etc).filter((name) => name.includes('candidate') || name.includes('tmp')), []);
});

test('enable honours INTERNAL_PORT and UPSTREAM_PORT and rejects non-numeric ports', (t) => {
  const f = fixture(t);
  assert.notEqual(f.run(['--dry-run', f.file], { INTERNAL_PORT: '80;id' }).status, 0);
  const result = f.run([f.file], { INTERNAL_PORT: '9001', UPSTREAM_PORT: '9002' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(f.read(), /ask http:\/\/127\.0\.0\.1:9001\/tls\/ask/);
  assert.match(f.read(), /reverse_proxy 127\.0\.0\.1:9002\n\}\n$/);
});

test('enable merges into an existing global block instead of adding a second one', (t) => {
  const content = `# edge\n{\n    email admin@example.test\n}\n${initial}`;
  const f = fixture(t, content);
  const result = f.run([f.file]);
  assert.equal(result.status, 0, result.stderr);
  const out = f.read();
  assert.equal(out.match(/^\{$/gm).length, 1);
  assert.equal(out, `# edge\n{\n    on_demand_tls {\n        ask http://127.0.0.1:8789/tls/ask\n    }\n    email admin@example.test\n}\n${initial}\n${siteBlock}`);
});

test('enable refuses a one-line global block it cannot merge safely', (t) => {
  const f = fixture(t, `{ email admin@example.test }\n${initial}`);
  const result = f.run([f.file]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Cannot merge/);
  assert.deepEqual(f.backups(), []);
});

test('enable refuses existing on_demand_tls and catch-all sites without writing anything', (t) => {
  const cases = [
    [`{\n    on_demand_tls {\n        ask http://127.0.0.1:1/x\n    }\n}\n${initial}`, /on_demand_tls/],
    [`${initial}https:// {\n    reverse_proxy 127.0.0.1:1\n}\n`, /catch-all/],
    [`${initial}  https://{\n}\n`, /catch-all/],
    [`${initial}https://, http:// {\n}\n`, /catch-all/],
  ];
  for (const [content, pattern] of cases) {
    const f = fixture(t, content);
    const result = f.run([f.file]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, pattern);
    assert.equal(f.read(), content);
    assert.deepEqual(readdirSync(f.etc), ['Caddyfile']);
    assert.deepEqual(f.callLog(), []);
  }
  // A named https:// site is not a catch-all.
  const f = fixture(t, `${initial}https://named.example.test {\n}\n`);
  assert.equal(f.run(['--dry-run', f.file]).status, 0);
});

test('failed validation leaves the live file untouched and never reloads', (t) => {
  const f = fixture(t);
  const result = f.run([f.file], { VALIDATE_STATUS: '1' });
  assert.notEqual(result.status, 0);
  assert.equal(f.read(), initial);
  assert.deepEqual(f.callLog().map((line) => line.split(' ')[0] + ' ' + line.split(' ')[1]), ['caddy validate']);
  assert.deepEqual(readdirSync(f.etc).filter((name) => name.includes('candidate') || name.includes('tmp')), []);
});

test('reload or health-check failure restores the backup and reloads again', (t) => {
  for (const env of [{ RELOAD_STATUS: '1' }, { ACTIVE_STATUS: '3' }]) {
    const f = fixture(t);
    const result = f.run([f.file], env);
    assert.notEqual(result.status, 0);
    assert.equal(f.read(), initial);
    assert.match(result.stderr, /Restored/);
    const reloads = f.callLog().filter((line) => line === 'systemctl reload caddy');
    assert.equal(reloads.length, 2);
    assert.deepEqual(readdirSync(f.etc).filter((name) => name.includes('candidate') || name.includes('tmp')), []);
  }
});

test('rollback restores a backup after validating it, keeping a pre-rollback copy', (t) => {
  const f = fixture(t);
  assert.equal(f.run([f.file]).status, 0);
  const enabled = f.read();
  const backup = join(f.etc, f.backups()[0]);
  writeFileSync(join(f.dir, 'calls'), '');
  const result = f.run(['--rollback', backup, f.file]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.read(), initial);
  const safety = readdirSync(f.etc).find((name) => name.includes('prerollback'));
  assert.equal(readFileSync(join(f.etc, safety), 'utf8'), enabled);
  const calls = f.callLog().filter(Boolean);
  assert.match(calls[0], /^caddy validate --adapter caddyfile --config /);
  assert.deepEqual(calls.slice(1), ['systemctl reload caddy', 'systemctl is-active --quiet caddy']);
});

test('rollback with a failing validate or reload does not leave a broken file', (t) => {
  const f = fixture(t);
  assert.equal(f.run([f.file]).status, 0);
  const enabled = f.read();
  const backup = join(f.etc, f.backups()[0]);
  assert.notEqual(f.run(['--rollback', backup, f.file], { VALIDATE_STATUS: '1' }).status, 0);
  assert.equal(f.read(), enabled);
  assert.notEqual(f.run(['--rollback', backup, f.file], { RELOAD_STATUS: '1' }).status, 0);
  assert.equal(f.read(), enabled, 'a failed reload puts the pre-rollback file back');
});

test('rollback refuses missing or symlinked backups', (t) => {
  const f = fixture(t);
  assert.notEqual(f.run(['--rollback', join(f.dir, 'missing'), f.file]).status, 0);
  symlinkSync(f.file, join(f.dir, 'link'));
  assert.notEqual(f.run(['--rollback', join(f.dir, 'link'), f.file]).status, 0);
  assert.notEqual(f.run(['--rollback']).status, 0);
  assert.equal(f.read(), initial);
});

test('usage errors, symlinked Caddyfile and non-root writes are refused', (t) => {
  const f = fixture(t);
  assert.notEqual(f.run(['--bogus']).status, 0);
  assert.notEqual(f.run([f.file, 'extra']).status, 0);
  assert.notEqual(f.run(['--dry-run', '--rollback', f.file, f.file]).status, 0);
  symlinkSync(f.file, join(f.dir, 'link'));
  assert.match(f.run([join(f.dir, 'link')]).stderr, /regular, non-symlink/);
  if (process.getuid() !== 0) {
    const real = spawnSync('bash', [script, f.file], { encoding: 'utf8', env: { ...process.env, BIN: join(f.dir, 'bin') } });
    assert.notEqual(real.status, 0);
    assert.match(real.stderr, /Run as root/);
    assert.equal(f.read(), initial);
  }
});

test('the default Caddyfile path is /etc/caddy/Caddyfile', () => {
  assert.match(readFileSync(script, 'utf8'), /caddyfile=\$\{1:-\/etc\/caddy\/Caddyfile\}/);
});
