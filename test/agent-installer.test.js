import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, statSync, rmSync, existsSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
const source = readFileSync('scripts/install-agent.sh', 'utf8');
const token = 'synthetic-private-token';
const image = source.match(/^image=(.+)$/m)[1];
const publishedImage = image.replace('DIGEST_PLACEHOLDER', 'a'.repeat(64));
function fixture(t, published = true) {
  const dir = mkdtempSync(join(tmpdir(), 'agent-install-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, 'bin'), config = join(dir, 'config'), units = join(dir, 'units');
  mkdirSync(bin); mkdirSync(units);
  const stub = (name, body) => writeFileSync(join(bin, name), `#!/bin/bash\n${body}\n`, { mode: 0o755 });
  stub('id', 'echo "${FAKE_UID:-0}"'); stub('uname', 'echo Linux');
  stub('docker', 'printf "docker %s\\n" "$*" >> "$CALLS"; exit "${DOCKER_EXIT:-0}"');
  stub('systemctl', 'printf "systemctl %s\\n" "$*" >> "$CALLS"; exit "${SYSTEMD_EXIT:-0}"');
  stub('chown', 'exit 0');
  stub('install', '/usr/bin/install -d -m 700 "${@: -1}"');
  for (const name of ['chmod', 'cat', 'rm']) symlinkSync(`/usr/bin/${name}`, join(bin, name));
  const script = join(dir, 'installer.sh');
  // Substitute a synthetic published digest and isolated filesystem destinations.
  writeFileSync(script, source.replace(image, published ? publishedImage : image).replace('config_dir=/etc/fastdog-agent', `config_dir=${config}`).replace('unit_dir=/etc/systemd/system', `unit_dir=${units}`));
  const calls = join(dir, 'calls');
  const run = (args, env = {}) => {
    const result = spawnSync('/bin/bash', [script, ...args], { encoding: 'utf8', env: { PATH: bin, CALLS: calls, FASTDOG_AGENT_TOKEN: token, ...env } });
    assert.ok(!`${result.stdout}${result.stderr}`.includes(token), 'token must never be printed');
    return result;
  };
  return { run, config, units, calls, bin };
}
const args = [ '--edge', 'wss://edge.example.test/_fastdog/tunnel', '--hostname', 'app.example.test', '--name', 'web-1'];
test('installer stores private configuration, starts the pinned container and removes it', (t) => {
  const f = fixture(t);
  const result = f.run(args); assert.equal(result.status, 0, result.stderr);
  const env = join(f.config, 'web-1.env');
  assert.equal(statSync(env).mode & 0o777, 0o600);
  assert.equal(readFileSync(env, 'utf8'), `AGENT_TOKEN=${token}\nAGENT_NAME=web-1\nAGENT_HOSTNAME=app.example.test\nAGENT_LOCAL_UPSTREAM=http://127.0.0.1:8080\nEDGE_HTTP_URL=https://edge.example.test\nEDGE_WS_URL=wss://edge.example.test/_fastdog/tunnel\n`);
  const unit = readFileSync(join(f.units, 'fastdog-agent-web-1.service'), 'utf8');
  assert.ok(unit.includes(`run --rm --name fastdog-agent-web-1 --env-file ${env} --network host ${publishedImage}`));
  assert.match(unit, /Restart=always/); assert.ok(!unit.includes(token));
  assert.match(readFileSync(f.calls, 'utf8'), /docker pull .*:0\.1\.0@sha256:[a-f0-9]{64}\nsystemctl daemon-reload\nsystemctl enable --now fastdog-agent-web-1.service/);
  assert.equal(f.run(args).status, 1, 'existing credentials are not replaced');
  assert.equal(f.run(['--uninstall', '--name', 'web-1']).status, 0);
  assert.equal(existsSync(env), false);
  assert.equal(existsSync(join(f.units, 'fastdog-agent-web-1.service')), false);
});
test('installer rejects invalid or missing input without exposing the token', (t) => {
  const f = fixture(t);
  for (const extra of [['--edge', 'http://edge.example.test'], ['--edge', 'https://edge.example.test:99999'], ['--edge', 'https://user:pass@edge.example.test'], ['--name', '../bad'], ['--name', 'Bad'], ['--hostname', 'bad\nHOST=x'], ['--origin', 'ftp://example.test'], ['--token', token + '\nBAD=x'], ['--unknown'], ['--origin']]) {
    assert.notEqual(f.run([...args, ...extra]).status, 0, extra[0]);
  }
  assert.notEqual(f.run([]).status, 0);
  assert.notEqual(f.run(['--token', token, '--edge', 'https://edge.example.test']).status, 0);
  assert.equal(existsSync(f.config), false);
});
test('installer explains missing prerequisites and pull failures', (t) => {
  const f = fixture(t);
  for (const [env, message] of [[{ FAKE_UID: '1000' }, /root/], [{ SYSTEMD_EXIT: '1' }, /systemd/], [{ DOCKER_EXIT: '1' }, /download/]]) {
    const r = f.run(args, env); assert.equal(r.status, 1); assert.match(r.stderr, message);
  }
  rmSync(join(f.bin, 'docker'));
  assert.match(f.run(args).stderr, /Install Docker/);
  writeFileSync(join(f.bin, 'docker'), '#!/bin/bash\nexit 0\n', { mode: 0o755 });
  rmSync(join(f.bin, 'systemctl'));
  assert.match(f.run(args).stderr, /requires systemd/);
});
test('portal installer is byte-identical and bash syntax is valid', () => {
  assert.deepEqual(readFileSync('portal/public/install/agent.sh'), Buffer.from(source));
  assert.equal(spawnSync('/bin/bash', ['-n', resolve('scripts/install-agent.sh')]).status, 0);
});
test('container uses only agent runtime files and the locked production dependency', () => {
  const manifest = JSON.parse(readFileSync('agent/package.json'));
  const lock = JSON.parse(readFileSync('agent/package-lock.json'));
  assert.equal(manifest.version, '0.1.0');
  assert.deepEqual(Object.keys(manifest.dependencies), ['ws']);
  assert.equal(lock.packages['node_modules/ws'].version, manifest.dependencies.ws);
  const docker = readFileSync('agent/Dockerfile', 'utf8');
  assert.match(docker, /^FROM node:20-bookworm-slim/m);
  assert.match(docker, /USER node/); assert.match(docker, /ENTRYPOINT \["node", "agent\/index.js"\]/);
  assert.ok(!/^ENV /m.test(docker));
  assert.match(docker, /COPY index.js backoff.js heartbeat.js .\/agent\//);
});

test('installer rejects argv tokens and missing or malformed environment tokens', (t) => {
  const f = fixture(t);
  for (const option of [['--token', token], [`--token=${token}`]]) {
    const result = f.run([...args, ...option]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /FASTDOG_AGENT_TOKEN/);
  }
  for (const value of ['', `${token}\nBAD=x`, `${token} space`]) {
    assert.equal(f.run(args, { FASTDOG_AGENT_TOKEN: value }).status, 1);
  }
  assert.equal(existsSync(f.calls), false);
});
test('placeholder blocks installation before any system command but allows removal', (t) => {
  const f = fixture(t, false);
  const result = f.run(args);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /published image digest/);
  assert.equal(existsSync(f.calls), false);
  assert.equal(existsSync(f.config), false);
  assert.equal(f.run(['--uninstall']).status, 0);
});
test('portal and installer each define the same single image reference', () => {
  const portal = readFileSync('portal/public/js/agent-view.js', 'utf8');
  assert.equal(portal.match(/const AGENT_IMAGE = '([^']+)'/)[1], image);
  for (const text of [source, portal]) assert.equal(text.split(image).length, 2);
  assert.match(image, /:0\.1\.0@sha256:DIGEST_PLACEHOLDER$/);
});
test('image publication uses tags only and rejects an existing registry tag before push', () => {
  const workflow = readFileSync('.github/workflows/agent-image.yml', 'utf8');
  assert.doesNotMatch(workflow, /workflow_dispatch/);
  assert.match(workflow, /tags: \['agent-v\*'\]/);
  const guard = workflow.slice(workflow.indexOf('if docker manifest inspect'), workflow.indexOf('- uses: docker/build-push-action'));
  assert.match(guard, /fastdog-agent:\$AGENT_VERSION/);
  assert.match(guard, /exit 1/);
});
