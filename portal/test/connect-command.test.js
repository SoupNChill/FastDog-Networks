import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createApp } from '../src/app.js';
import { fixture } from './helpers.js';

test('connect command gets the configured edge URL and tracks whether a command was issued', async (t) => {
  const f = await fixture(t, { edgeUrl: 'https://edge.example.test' });
  const a = await f.seed(0), b = await f.seed(1);
  const path = '/api/hostnames/app.example.test';
  assert.equal((await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' })).status, 201);
  const verified = await a.client.call(`${path}/verify`, 'POST');
  assert.equal(verified.data.credential.agent_env.EDGE_HTTP_URL, 'https://edge.example.test');
  assert.equal(verified.data.credential.agent_env.EDGE_WS_URL, 'wss://edge.example.test/_fastdog/tunnel');
  assert.equal(verified.data.credential.agent_env.AGENT_LOCAL_UPSTREAM, undefined);
  const issued = async (client) => (await client.call('/api/hostnames')).data.hostnames.map((h) => h.command_issued);
  assert.deepEqual(await issued(a.client), [false]);
  const rotated = await a.client.call(`${path}/rotate`, 'POST');
  assert.equal(rotated.data.credential.agent_env.EDGE_HTTP_URL, 'https://edge.example.test');
  assert.deepEqual(await issued(a.client), [true]);
  assert.deepEqual(await issued(b.client), []);
  assert.equal((await a.client.call(path, 'DELETE')).status, 200);
  assert.equal((await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' })).status, 201);
  assert.deepEqual(await issued(a.client), [false]);
});

test('without an edge URL no edge address is invented; bad edge URLs refuse to start', async (t) => {
  const f = await fixture(t);
  const a = await f.seed(0);
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  const verified = await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  assert.equal(verified.data.credential.agent_env.EDGE_HTTP_URL, undefined);
  for (const edgeUrl of ['http://edge.example.test', 'https://edge.example.test/path', 'not a url', "https://edge.example.test'"]) {
    assert.throws(() => createApp({ dataDir: f.dataDir, edge: {}, config: { origin: 'https://portal.example.test', edgeUrl } }), /Invalid public edge URL/);
  }
});

test('Connect page asks where the app runs, has one primary action and an inline check result', () => {
  const html = readFileSync(new URL('../public/connect.html', import.meta.url), 'utf8');
  const view = readFileSync(new URL('../public/js/agent-view.js', import.meta.url), 'utf8');
  assert.match(html, /<label for="origin">Where does your app run on that server\?<\/label>/);
  assert.match(html, /must already be running on that server/);
  assert.doesNotMatch(html + view, /Show connection|placeholders/i);
  assert.match(html, /id="check-agent"[^]*id="connection" role="status" aria-live="polite"[^]*id="checked-at"/);
  assert.match(view, /Get my connect command/);
  assert.match(view, /warning\.hidden = !issued/);
  assert.match(view, /Checked at /);
  const css = readFileSync(new URL('../public/css/connect.css', import.meta.url), 'utf8');
  assert.match(css, /prefers-reduced-motion: reduce/);
});

test('restricted origins and allowed local origins agree across builders', async () => {
  const server = await import('../src/connect-command.js');
  const browser = await import('../public/js/agent-view.js');
  const blocked = ['169.254.0.0', '169.254.255.255', '[fe80::1]', '[febf:ffff::1]', '[fd00:ec2::1]',
    '[64:ff9b::]', '[64:ff9b::ffff:ffff]', '[0064:ff9b:0:0:0:0:a9fe:a9fe]',
    '100.64.0.0', '100.100.100.200', '100.127.255.255', '0.0.0.0', '0', '0x64400000',
    '[::ffff:100.100.100.200]', '[::ffff:0.0.0.0]', '[::ffff:169.254.1.1]'];
  for (const host of blocked) {
    const origin = `http://${host}:5000`;
    assert.equal(server.validOrigin(origin), null, origin);
    assert.equal(server.originError(origin), server.LINK_LOCAL_ERROR, origin);
    assert.equal(browser.validateOrigin(origin).error, server.LINK_LOCAL_ERROR, origin);
  }
  for (const host of ['metadata', 'app', 'localhost.', '100.63.255.255', '100.128.0.0', '[64:ff9a::1]', '[64:ff9b:0:0:0:1::]']) {
    const origin = `http://${host}:5000`;
    assert.equal(server.validOrigin(origin), null, origin);
    assert.ok(browser.validateOrigin(origin).error, origin);
    assert.equal(server.originError(origin), null, 'outside restricted ranges');
  }
  for (const host of ['localhost', 'host.docker.internal', '127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '[::1]', '[fd00:ec3::1]']) {
    const origin = `http://${host}:5000`;
    assert.equal(server.validOrigin(origin), origin);
    assert.equal(browser.validateOrigin(origin).value, origin);
    const env = { AGENT_TOKEN: 'synthetic-token', AGENT_HOSTNAME: 'app.example.test', EDGE_HTTP_URL: 'https://edge.example.test' };
    assert.equal(server.buildCommand(env, { platform: 'docker', origin }), browser.connectionCommand(env, 'docker', 'https://portal.example.test', origin));
  }
  assert.equal(browser.LINK_LOCAL_ERROR, server.LINK_LOCAL_ERROR);
});

test('Docker shell replaces stale env symlinks and cleans up failures without expansion', async (t) => {
  const { mkdtempSync, writeFileSync, symlinkSync, existsSync, statSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { spawnSync } = await import('node:child_process');
  const { buildCommand, agentSuffix } = await import('../src/connect-command.js');
  const dir = mkdtempSync(join(tmpdir(), 'connect-shell-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const env = { AGENT_TOKEN: 'synthetic-token', AGENT_HOSTNAME: 'app.example.test', EDGE_HTTP_URL: 'https://edge.example.test' };
  const command = buildCommand(env, { platform: 'docker', origin: '127.0.0.1:5000' });
  assert.doesNotMatch(command, /\$/);
  const envPath = join(dir, `fastdog-agent-${agentSuffix(env.AGENT_HOSTNAME)}.env`);
  const target = join(dir, 'untouched');
  writeFileSync(target, 'unchanged');
  for (const failure of ['none', 'pull', 'run']) {
    rmSync(envPath, { force: true });
    symlinkSync(target, envPath);
    writeFileSync(join(dir, 'docker'), `#!/bin/sh\ncase "$1" in ${failure}) exit 1;; esac\nexit 0\n`, { mode: 0o700 });
    const result = spawnSync('sh', ['-c', command], { cwd: dir, env: { ...process.env, PATH: `${dir}:${process.env.PATH}` } });
    assert.equal(result.status, failure === 'none' ? 0 : 1);
    assert.equal(readFileSync(target, 'utf8'), 'unchanged');
    assert.equal(existsSync(envPath), failure === 'none');
    if (failure === 'none') assert.equal(statSync(envPath).mode & 0o777, 0o600);
  }
});

test('assistant cleanup examples use a concrete env filename and require exact substitution', () => {
  for (const path of ['../../site/llms.txt', '../src/connect-tokens.js']) {
    const text = readFileSync(new URL(path, import.meta.url), 'utf8');
    assert.match(text, /fastdog-agent-app-example-test-0123456789\.env/);
    assert.match(text, /substitute the exact name from the command/);
    assert.doesNotMatch(text, /fastdog-agent-<[^\n]*?\.env/);
  }
});
