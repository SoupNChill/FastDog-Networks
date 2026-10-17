import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const liveHttp = JSON.parse(readFileSync(resolve('test/fixtures/caddy-adapted-live-fdctl.json'), 'utf8'));
const script = resolve('deploy/caddy/enable-on-demand-tls.sh');
const initial = '(fdlog) {}\n(fdctl) {\n    @ctl path /_fastdog/*\n}\nexisting.example.test {\n    import fdlog existing.example.test\n    reverse_proxy 127.0.0.1:8787\n}\n';
const globalBlock = '{\n    on_demand_tls {\n        ask http://127.0.0.1:8789/tls/ask\n    }\n}\n';
const siteBlock = 'https:// {\n    tls {\n        on_demand\n    }\n    @sni_mismatch not host {http.request.tls.server_name}\n    respond @sni_mismatch 421\n    import fdctl\n    reverse_proxy 127.0.0.1:8787\n}\n';

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
if [ "$1" = adapt ]; then
  case "$*" in *candidate-ondemand-*) ;; *) [ "\${POST_ADAPT_FAIL:-0}" = 1 ] && exit 1 ;; esac
  printf '%s' "\${ADAPT_JSON:-}"
  exit "\${ADAPT_STATUS:-0}"
fi
if [ "$1" = validate ]; then
  while [ $# -gt 0 ]; do [ "$1" = --config ] && cp "$2" '${dir}/validated'; shift; done
fi
exit "\${VALIDATE_STATUS:-0}"
`, { mode: 0o755 });
  writeFileSync(join(bin, 'systemctl'), `#!/bin/sh
printf 'systemctl %s\\n' "$*" >> '${calls}'
case "$1" in
  reload) exit "\${RELOAD_STATUS:-0}" ;;
  restart) : > '${dir}/restarted'; exit "\${RESTART_STATUS:-0}" ;;
  is-active) if [ -e '${dir}/restarted' ]; then exit "\${ACTIVE_AFTER_RESTART:-\${ACTIVE_STATUS:-0}}"; fi; exit "\${ACTIVE_STATUS:-0}" ;;
esac
`, { mode: 0o755 });
  writeFileSync(join(bin, 'curl'), `#!/bin/sh
printf 'curl %s\\n' "$*" >> '${calls}'
printf '%s' "\${ASK_STATUS:-404}"
exit "\${CURL_STATUS:-0}"
`, { mode: 0o755 });
  // Only the fixture copy's UID check changes; the original's root refusal is tested separately.
  const fixtureScript = join(dir, 'enable.sh');
  writeFileSync(fixtureScript, readFileSync(script, 'utf8').replace('[[ $EUID == 0 ]]', '[[ 0 == 0 ]]'));
  const run = (args = [], extra = {}) => spawnSync('bash', [fixtureScript, ...args],
    { encoding: 'utf8', env: { ...process.env, BIN: bin, HEALTH_DELAY: '0',
      ADAPT_JSON: JSON.stringify({ apps: { http: liveHttp } }), ...extra } });
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
  assert.match(calls[1], /caddy adapt .*Caddyfile\.candidate-ondemand-/);
  assert.deepEqual(calls.slice(2, 5), ['systemctl reload caddy', 'systemctl is-active --quiet caddy',
    'curl --noproxy * -sS --max-time 3 -o /dev/null -w %{http_code} http://127.0.0.1:8789/tls/ask?domain=probe.invalid']);
  assert.deepEqual(readdirSync(f.etc).filter((name) => name.includes('candidate') || name.includes('tmp')), []);
});

test('an unhealthy ask endpoint after reload restores the backup and reloads again', (t) => {
  const f = fixture(t);
  const result = f.run([f.file], { CURL_STATUS: '7' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /not healthy/);
  assert.match(result.stderr, /Restored/);
  assert.equal(f.read(), initial);
  assert.equal(f.callLog().filter((line) => line.startsWith('curl')).length, 3, 'retried before giving up');
  assert.equal(f.callLog().filter((line) => line === 'systemctl reload caddy').length, 2);
  assert.deepEqual(readdirSync(f.etc).filter((name) => name.includes('enabled-ondemand')), []);
});

test('the temporary install file is removed when the script is interrupted mid-install', (t) => {
  const f = fixture(t);
  // The script keeps the tmp path in its cleanup trap; a failing mv leaves nothing behind.
  const source = readFileSync(script, 'utf8');
  assert.match(source, /\[\[ -z \$tmp \]\] \|\| rm -f -- "\$tmp"/);
  writeFileSync(join(f.dir, 'bin', 'mv'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
  const result = f.run([f.file], { PATH: `${join(f.dir, 'bin')}:${process.env.PATH}` });
  assert.notEqual(result.status, 0);
  assert.equal(f.read(), initial);
  assert.deepEqual(readdirSync(f.etc).filter((name) => name.includes('tmp') || name.includes('candidate')), []);
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
    assert.deepEqual(readdirSync(f.etc).filter((name) => name !== 'Caddyfile.lock'), ['Caddyfile']);
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
  for (const env of [{ RELOAD_STATUS: '1' }, { ACTIVE_STATUS: '3', ACTIVE_AFTER_RESTART: '0' }]) {
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

test('rollback refuses when the Caddyfile changed since enabling unless --force', (t) => {
  const f = fixture(t);
  assert.equal(f.run([f.file]).status, 0);
  const backup = join(f.etc, f.backups()[0]);
  const edited = `${f.read()}\nadded.example.test {\n    reverse_proxy 127.0.0.1:8787\n}\n`;
  writeFileSync(f.file, edited);
  const refused = f.run(['--rollback', backup, f.file]);
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /changed since/);
  assert.match(refused.stderr, /diff -u .*enabled-ondemand-.*Caddyfile/);
  assert.match(refused.stderr, /--force/);
  assert.equal(f.read(), edited);
  assert.deepEqual(readdirSync(f.etc).filter((name) => name.includes('prerollback')), []);
  const forced = f.run(['--rollback', backup, '--force', f.file]);
  assert.equal(forced.status, 0, forced.stderr);
  assert.equal(f.read(), initial);
  const safety = readdirSync(f.etc).find((name) => name.includes('prerollback'));
  assert.equal(readFileSync(join(f.etc, safety), 'utf8'), edited);
  // --force is only meaningful with --rollback, and a backup with no enable record needs it too.
  assert.notEqual(f.run(['--force', f.file]).status, 0);
  const g = fixture(t);
  writeFileSync(join(g.etc, 'Caddyfile.bak-ondemand-manual'), initial);
  const missing = g.run(['--rollback', join(g.etc, 'Caddyfile.bak-ondemand-manual'), g.file]);
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /No record/);
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

test('restore falls back to a restart when the reload keeps failing', (t) => {
  const f = fixture(t);
  const result = f.run([f.file], { RELOAD_STATUS: '1', ACTIVE_STATUS: '3', ACTIVE_AFTER_RESTART: '0' });
  assert.equal(result.status, 1);
  assert.equal(f.read(), initial);
  assert.match(result.stderr, /restarting caddy/);
  assert.match(result.stderr, /Restored/);
  const calls = f.callLog();
  assert.ok(calls.includes('systemctl restart caddy'));
  // The restored file is validated before the second reload.
  assert.match(calls[calls.indexOf('systemctl restart caddy') - 2], /^caddy validate/);
});

test('restore does not claim success and exits 3 when caddy stays down', (t) => {
  const f = fixture(t);
  const result = f.run([f.file], { RELOAD_STATUS: '1', ACTIVE_STATUS: '3' });
  assert.equal(result.status, 3);
  assert.match(result.stderr, /CADDY IS DOWN/);
  assert.doesNotMatch(result.stderr, /Restored/);
  assert.equal(f.read(), initial);
});

test('rollback restore failures: restart recovers, or exit 3 when caddy stays down', (t) => {
  const f = fixture(t);
  assert.equal(f.run([f.file]).status, 0);
  const enabled = f.read();
  const backup = join(f.etc, f.backups()[0]);
  const recovered = f.run(['--rollback', backup, f.file], { RELOAD_STATUS: '1', ACTIVE_STATUS: '3', ACTIVE_AFTER_RESTART: '0' });
  assert.equal(recovered.status, 1);
  assert.equal(f.read(), enabled);
  assert.match(recovered.stderr, /Restored/);
  assert.ok(f.callLog().includes('systemctl restart caddy'));
  rmSync(join(f.dir, 'restarted'), { force: true });
  const down = f.run(['--rollback', backup, f.file], { RELOAD_STATUS: '1', ACTIVE_STATUS: '3', ACTIVE_AFTER_RESTART: '3' });
  assert.equal(down.status, 3);
  assert.match(down.stderr, /CADDY IS DOWN/);
  assert.doesNotMatch(down.stderr, /Restored/);
});

test('enable refuses a Caddyfile without the (fdctl) snippet', (t) => {
  const content = 'existing.example.test {\n    reverse_proxy 127.0.0.1:8787\n}\n';
  for (const args of [['--dry-run'], []]) {
    const f = fixture(t, content);
    const result = f.run([...args, f.file]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /\(fdctl\)/);
    assert.equal(f.read(), content);
    assert.deepEqual(f.backups(), []);
    assert.equal(f.callLog().length, 0);
  }
});

test('the lock is a sidecar file, not the Caddyfile', (t) => {
  const f = fixture(t);
  assert.equal(f.run([f.file]).status, 0);
  assert.ok(existsSync(`${f.file}.lock`));
});

test('the default Caddyfile path is /etc/caddy/Caddyfile', () => {
  assert.match(readFileSync(script, 'utf8'), /caddyfile=\$\{1:-\/etc\/caddy\/Caddyfile\}/);
});


test('enable rolls back on non-denial responses and missing catch-all protection', (t) => {
  const namedOnly = { apps: { http: { servers: { srv0: { listen: [':443'], routes: [
    { match: [{ host: ['named.example.test'] }], handle: [{ handler: 'subroute', routes: [
      { match: [{ path: ['/_fastdog/*'] }] }
    ] }] }
  ] } } } } };
  for (const env of [{ ASK_STATUS: '200' }, { ASK_STATUS: '302' }, { ASK_STATUS: '503' },
    { ADAPT_STATUS: '1' }, { ADAPT_JSON: '{}' }, { ADAPT_JSON: 'invalid' }, { ADAPT_JSON: JSON.stringify(namedOnly) }]) {
    const f = fixture(t);
    const result = f.run([f.file], env);
    assert.notEqual(result.status, 0);
    assert.equal(f.read(), initial);
    if (env.ASK_STATUS) assert.match(result.stderr, /Restored/);
    else assert.ok(!f.callLog().some(line => line.startsWith('systemctl')));
  }
});

test('probe-host requires 200 and fallback warns that enablement is unconfirmed', (t) => {
  const f = fixture(t);
  const result = f.run(['--probe-host', 'static.example.test', f.file], { ASK_STATUS: '200' });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(f.callLog().some(line => line.includes('domain=static.example.test')));
  assert.doesNotMatch(result.stderr, /cannot confirm/);
  const g = fixture(t);
  assert.match(g.run([g.file]).stderr, /cannot confirm/);
  const h = fixture(t);
  assert.notEqual(h.run(['--probe-host', 'static.example.test', h.file]).status, 0);
  assert.equal(h.read(), initial);
});

test('adapted catch-all must include the mismatch 421 response', (t) => {
  for (const route of [
    { match: [{ expression: '{http.request.host} != {http.request.tls.server_name}' }], handle: [{ handler: 'static_response', status_code: 421 }] },
    { match: [{ not: [{ host: ['wrong.example.test'] }] }], handle: [{ handler: 'static_response', status_code: 421 }] },
    { match: [{ not: [{ host: ['{http.request.tls.server_name}'] }] }], handle: [{ handler: 'static_response', status_code: 200 }] },
    { match: [{ host: ['named.example.test'], not: [{ host: ['{http.request.tls.server_name}'] }] }], handle: [{ handler: 'static_response', status_code: 421 }] },
    { handle: [{ handler: 'static_response', status_code: 421 }] }
  ]) {
    const f = fixture(t);
    const config = { apps: { http: { servers: { srv0: { listen: [':443'], routes: [
      { handle: [{ handler: 'subroute', routes: [
        route, { match: [{ path: ['/_fastdog/*'] }], handle: [{ handler: 'static_response', status_code: 404 }] }
      ] }] }
    ] } } } } };
    assert.notEqual(f.run([f.file], { ADAPT_JSON: JSON.stringify(config) }).status, 0);
    assert.equal(f.read(), initial);
  }
});

test('signal immediately after rename restores enable and rollback files', (t) => {
  for (const rollback of [false, true]) {
    const f = fixture(t);
    let args = [f.file];
    if (rollback) {
      assert.equal(f.run(args).status, 0);
      args = ['--rollback', join(f.etc, f.backups()[0]), f.file];
    }
    const before = f.read();
    writeFileSync(join(f.dir, 'bin', 'mv'), `#!/bin/sh
/bin/mv "$@" || exit 1
if [ ! -e '${f.dir}/signalled' ]; then
  touch '${f.dir}/signalled'
  kill -TERM "$PPID"
fi
`, { mode: 0o755 });
    const result = f.run(args, { PATH: `${join(f.dir, 'bin')}:${process.env.PATH}` });
    assert.notEqual(result.status, 0);
    assert.equal(f.read(), before);
    assert.match(result.stderr, /Restored/);
  }
});

test('catch-all control route must actually refuse requests with a 4xx handler', (t) => {
  for (const handler of [
    { handler: 'reverse_proxy', status_code: 404 },
    { handler: 'static_response', status_code: 200 },
    { handler: 'static_response', status_code: 500 },
    { handler: 'error', status_code: 403 },
    { handler: 'static_response', status_code: '404' },
  ]) {
    const f = fixture(t);
    const config = { apps: { http: { servers: { srv0: { listen: [':443'], routes: [
      { handle: [{ handler: 'subroute', routes: [
        { match: [{ not: [{ host: ['{http.request.tls.server_name}'] }] }], handle: [{ handler: 'static_response', status_code: 421 }] },
        { match: [{ path: ['/_fastdog/*'] }], handle: [handler] },
      ] }] },
      { handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: '127.0.0.1:8787' }] }] },
    ] } } } } };
    const accepted = ['error', 'static_response'].includes(handler.handler) && /^4[0-9]{2}$/.test(String(handler.status_code));
    const result = f.run([f.file], { ADAPT_JSON: JSON.stringify(config) });
    assert.equal(result.status === 0, accepted, result.stderr);
    if (!accepted) assert.equal(f.read(), initial);
  }
});

test('post-reload adaptation remains a second pass with rollback', (t) => {
  const f = fixture(t);
  const result = f.run([f.file], { POST_ADAPT_FAIL: '1' });
  assert.notEqual(result.status, 0);
  assert.equal(f.read(), initial);
  assert.match(result.stderr, /Restored/);
  assert.equal(f.callLog().filter(line => line.startsWith('caddy adapt')).length, 2);
});

const adaptedWith = (routes) => JSON.stringify({ apps: { http: { servers: { srv0: { listen: [':443'], routes } } } } });
const [liveControl, liveMismatch, liveProxy] = liveHttp.servers.srv0.routes;

test('the real adapted live fdctl form is accepted; missing, weak or misordered protections are rejected', (t) => {
  const proxy = { handler: 'reverse_proxy', upstreams: [{ dial: '127.0.0.1:8787' }] };
  const cases = [
    [[liveControl, liveMismatch, liveProxy], true],
    [[liveMismatch, liveProxy], false],
    [[{ match: liveControl.match, handle: [proxy] }, liveMismatch, liveProxy], false],
    [[{ match: liveControl.match, handle: [{ handler: 'static_response', status_code: 200 }] }, liveMismatch, liveProxy], false],
    [[{ match: liveControl.match, handle: [{ handler: 'subroute', routes: [{ handle: [{ handler: 'static_response', status_code: 200 }] }] }] }, liveMismatch, liveProxy], false],
    [[liveControl, liveProxy], false],
    [[liveProxy, liveControl, liveMismatch], false],
    [[liveControl, { handle: [proxy] }, liveMismatch], false],
    // Protection nested under a matcher-bearing parent is conditional.
    [[{ match: [{ method: ['GET'] }], handle: [{ handler: 'subroute', routes: [liveControl, liveMismatch] }] }, liveProxy], false],
    [[{ handle: [{ handler: 'subroute', routes: [liveControl, liveMismatch] }] }, liveProxy], true],
    // Any host-less reverse_proxy is the boundary, whatever its upstream form.
    [[{ handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: 'localhost:8787' }] }] }, liveControl, liveMismatch], false],
    [[liveControl, liveMismatch, { handle: [{ handler: 'reverse_proxy', upstreams: [{ dial: 'localhost:8787' }] }] }], true],
    // No proxy at all fails closed.
    [[liveControl, liveMismatch], false],
    // Control match must be path-only; a proxy before the terminal inner route is rejected.
    [[{ ...liveControl, match: [{ ...liveControl.match[0], method: ['GET'] }] }, liveMismatch, liveProxy], false],
    [[{ ...liveControl, match: [{ path: ['/_fastdog/*'], remote_ip: { ranges: ['10.0.0.0/8'] } }] }, liveMismatch, liveProxy], false],
    [[{ match: liveControl.match, handle: [{ handler: 'subroute', routes: [{ match: [{ method: ['GET'] }], handle: [proxy] }, { handle: [{ handler: 'static_response', status_code: 404 }] }] }] }, liveMismatch, liveProxy], false],
    [[{ match: liveControl.match, handle: [{ handler: 'subroute', routes: [{ match: [{ method: ['GET'] }], handle: [{ handler: 'static_response', status_code: 404 }] }] }] }, liveMismatch, liveProxy], false]
  ];
  for (const [routes, accepted] of cases) {
    const f = fixture(t);
    const result = f.run([f.file], { ADAPT_JSON: adaptedWith(routes) });
    assert.equal(result.status === 0, accepted, result.stderr);
    if (!accepted) assert.equal(f.read(), initial);
  }
});

test('the full live adapted form with a flattened catch-all wrapper is accepted; proxy-first inside it is rejected', (t) => {
  const full = JSON.parse(readFileSync(resolve('test/fixtures/caddy-adapted-live-full.json'), 'utf8'));
  const [hostRoute, wrapper] = full.servers.srv0.routes;
  const [control, mismatch, proxy] = wrapper.handle[0].routes;
  const withInner = inner => ({ servers: { srv0: { listen: [':443'], routes: [hostRoute,
    { handle: [{ handler: 'subroute', routes: inner }], terminal: true }] } } });
  for (const [http, accepted] of [[full, true], [withInner([proxy, control, mismatch]), false], [withInner([control, proxy, mismatch]), false]]) {
    const f = fixture(t);
    const result = f.run([f.file], { ADAPT_JSON: JSON.stringify({ apps: { http } }) });
    assert.equal(result.status === 0, accepted, result.stderr);
    if (!accepted) assert.equal(f.read(), initial);
  }
});

test('--check-only validates a copy anywhere without touching or writing beside it', (t) => {
  const f = fixture(t);
  const copyDir = join(f.dir, 'copy');
  mkdirSync(copyDir);
  const copy = join(copyDir, 'Caddyfile');
  writeFileSync(copy, initial);
  const result = f.run(['--check-only', copy]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /CHECK OK/);
  assert.equal(readFileSync(copy, 'utf8'), initial);
  assert.deepEqual(readdirSync(copyDir), ['Caddyfile']);
  assert.ok(f.callLog().some(line => line.startsWith('caddy validate')));
  assert.ok(!f.callLog().some(line => /^(systemctl|curl)/.test(line)));
  const bad = f.run(['--check-only', copy], { ADAPT_JSON: adaptedWith([liveProxy]) });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /CHECK FAILED/);
  assert.deepEqual(readdirSync(copyDir), ['Caddyfile']);
  assert.notEqual(f.run(['--check-only', '--dry-run', copy]).status, 0);
});
