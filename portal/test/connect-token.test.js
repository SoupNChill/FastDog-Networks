import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, tids, request } from './helpers.js';
import { buildCommand, validOrigin, originError } from '../src/connect-command.js';

const edgeUrl = 'https://edge.example-edge.test';
const bearer = (token) => ({ authorization: `Bearer ${token}` });
async function ready(t, config = {}) {
  const f = await fixture(t, { edgeUrl, docsUrl: 'https://docs.example.test', ...config });
  const a = await f.seed();
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  return { f, a };
}

test('connect tokens need an active owned hostname, CSRF and a verified session', async (t) => {
  const { f, a } = await ready(t);
  assert.equal((await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).status, 409);
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  assert.equal((await request(f.port, '/api/hostnames/app.example.test/connect-token', { method: 'POST' })).status, 401);
  const b = await f.seed(1);
  assert.equal((await b.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).status, 404);
  const issued = await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST');
  assert.equal(issued.status, 201);
  assert.match(issued.data.token, /^fdct_[A-Za-z0-9_-]{43}$/);
  assert.equal(issued.data.scope, 'connect');
  assert.equal(Date.parse(issued.data.expires_at) - f.now(), 3600000);
  assert.ok(issued.data.prompt.includes(issued.data.token));
  assert.ok(issued.data.prompt.includes('app.example.test'));
  assert.ok(issued.data.prompt.includes('https://docs.example.test/llms.txt'));
  const headerFile = '~/.config/fastdog/app.example.test.token.header';
  assert.ok(issued.data.prompt.includes('-H @/absolute/path/app.example.test.token.header'), 'permission-friendly per-hostname header file');
  assert.ok(!issued.data.prompt.includes('auth.header'));
  assert.ok(issued.data.prompt.includes(`: ' mkdir -p ~/.config/fastdog && (umask 077; printf 'Authorization: Bearer %s\\n' '${issued.data.token}' > ${headerFile})`), 'one-time user-run key setup with leading space');
  assert.ok(issued.data.prompt.includes('HISTCONTROL=ignorespace') && issued.data.prompt.includes('delete it from my history'));
  assert.ok(issued.data.prompt.includes(`I can delete ${headerFile}`), 'delete the header file after connecting');
  assert.ok(issued.data.prompt.includes('Never use curl -v or --trace'));
  assert.ok(issued.data.prompt.includes('curl 7.75 or newer') && issued.data.prompt.includes('umask 077 first'));
  assert.ok(issued.data.prompt.includes('ask me to run this one-time command') && issued.data.prompt.includes('do not write the header file yourself'));
  assert.ok(issued.data.prompt.includes('HOME may differ') && issued.data.prompt.includes('only ask which port'));
  assert.ok(issued.data.prompt.includes('curl --create-file-mode 0600 -o /absolute/path/fastdog-connect.json') && issued.data.prompt.includes('delete the file'));
  assert.ok(!/curl -o |chmod [0-7]{3}/.test(issued.data.prompt), 'no umask/chmod reliance for the connect response');
  const prompt = issued.data.prompt;
  assert.ok(prompt.includes('"platform": "docker"') && prompt.includes('docker info works without sudo') && prompt.includes('docker ps --filter name=fastdog-agent'));
  for (const needle of ['Never print the command', 'docker inspect', '/proc/*/cmdline', 'never echo the token', 'sh /absolute/path/fastdog-run.sh', 'whether it succeeded or failed', 'root-equivalent', 'ALREADY', 'rootless Docker']) assert.ok(prompt.includes(needle), needle);
  assert.ok(!prompt.includes('sh -c'));
  assert.ok(prompt.indexOf('docker info') < prompt.indexOf('systemd installer'), 'Docker before systemd');
  assert.ok(prompt.indexOf('"docker"') < prompt.indexOf('(use "linux" only'));
  assert.ok(issued.data.prompt.includes('every 15 seconds') && issued.data.prompt.includes('3 a day'));
  const stored = JSON.stringify(f.store.read('connect_tokens', []));
  assert.equal(stored.includes(issued.data.token), false, 'only a digest is stored');
  const list = await a.client.call('/api/hostnames/app.example.test/connect-token');
  assert.equal(list.data.tokens.length, 1);
  assert.equal(JSON.stringify(list.data).includes('fdct_'), false);
});

test('a connect token reads one hostname and issues its command exactly once', async (t) => {
  const { f, a } = await ready(t);
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const { token } = (await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).data;
  assert.equal((await request(f.port, '/api/connect/v1/hostname')).status, 401);
  assert.equal((await request(f.port, '/api/connect/v1/hostname', { headers: bearer('fdct_nope') })).status, 401);
  assert.equal((await request(f.port, `/api/connect/v1/hostname?token=${token}`)).status, 401, 'never accepted in the URL');
  const status = await request(f.port, '/api/connect/v1/hostname', { headers: bearer(token) });
  assert.equal(status.status, 200);
  assert.equal(status.data.hostname, 'app.example.test');
  assert.equal(status.data.agent.connected, false);
  assert.equal((await request(f.port, '/api/connect/v1/command', { headers: bearer(token) })).status, 405);
  const post = (body) => request(f.port, '/api/connect/v1/command', { method: 'POST', headers: { ...bearer(token), 'content-type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await post({ origin: 'http://203.0.113.9:80' })).status, 400, 'public origins are refused');
  assert.equal((await post({ origin: 'http://127.0.0.1:3000', platform: 'windows' })).status, 400);
  const command = await post({ origin: '127.0.0.1:4007' });
  assert.equal(command.status, 200);
  assert.match(command.data.command, /install\/agent\.sh/);
  assert.match(command.data.command, /--hostname 'app\.example\.test'/);
  assert.match(command.data.command, /--origin 'http:\/\/127\.0\.0\.1:4007'/);
  assert.match(command.data.command, /--edge 'https:\/\/edge\.example-edge\.test'/);
  assert.deepEqual(f.calls.at(-1), ['rotate', tids[0], 'app.example.test']);
  assert.equal((await post({ origin: '127.0.0.1:4007' })).status, 409, 'single use');
  const again = await request(f.port, '/api/connect/v1/hostname', { headers: bearer(token) });
  assert.equal(again.data.command_issued, true);
});

test('connect tokens expire after an hour and are revocable, including by removing the hostname', async (t) => {
  const { f, a } = await ready(t);
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const first = (await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).data.token;
  f.advance(3600001);
  assert.equal((await request(f.port, '/api/connect/v1/hostname', { headers: bearer(first) })).status, 401);
  const second = (await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).data.token;
  assert.equal((await request(f.port, '/api/connect/v1/hostname', { headers: bearer(second) })).status, 200);
  const revoked = await a.client.call('/api/hostnames/app.example.test/connect-token', 'DELETE');
  assert.equal(revoked.data.revoked, 1);
  assert.equal((await request(f.port, '/api/connect/v1/hostname', { headers: bearer(second) })).status, 401);
  const third = (await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).data.token;
  await a.client.call('/api/hostnames/app.example.test', 'DELETE');
  assert.equal((await request(f.port, '/api/connect/v1/hostname', { headers: bearer(third) })).status, 401);
});

test('issuing is rate limited and keeps at most three live tokens per hostname', async (t) => {
  const { f, a } = await ready(t);
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const tokens = [];
  for (let i = 0; i < 5; i++) tokens.push((await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).data.token);
  assert.equal((await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).status, 429);
  const live = [];
  for (const token of tokens) live.push((await request(f.port, '/api/connect/v1/hostname', { headers: bearer(token) })).status);
  assert.deepEqual(live, [401, 401, 200, 200, 200]);
});

test('server-side command builder matches the browser rules', async () => {
  assert.equal(validOrigin('127.0.0.1:5000'), 'http://127.0.0.1:5000');
  assert.equal(validOrigin('http://example.com:80'), null);
  assert.equal(validOrigin('http://127.0.0.1'), null);
  assert.equal(validOrigin("http://127.0.0.1:5000/'x"), null);
  const env = { AGENT_TOKEN: 'fake', AGENT_HOSTNAME: 'app.example.test', EDGE_HTTP_URL: 'https://edge.example-edge.test' };
  assert.equal(buildCommand(env, { platform: 'windows', portalOrigin: 'https://portal.example.test', origin: '127.0.0.1:1' }), null);
  const docker = buildCommand(env, { platform: 'docker', portalOrigin: 'https://portal.example.test', origin: '127.0.0.1:1' });
  assert.match(docker, /^umask 077; docker pull \S+ && printf .* && chmod 600 \S+ && \{ docker rm -f fastdog-agent-app-example-test-[0-9a-f]{10} .*docker run -d --name fastdog-agent-app-example-test-[0-9a-f]{10} --network host --cap-drop ALL --security-opt no-new-privileges --restart unless-stopped --env-file fastdog-agent-app-example-test-[0-9a-f]{10}\.env /);
  assert.ok(docker.indexOf('docker pull') < docker.indexOf('printf') && docker.indexOf('printf') < docker.indexOf('docker rm -f') && docker.indexOf('docker rm -f') < docker.indexOf('docker run'), 'pull before the token file is written');
  const nameOf = (hostname) => buildCommand({ ...env, AGENT_HOSTNAME: hostname }, { platform: 'docker', portalOrigin: 'https://portal.example.test', origin: '127.0.0.1:1' }).match(/--name (\S+)/)[1];
  assert.notEqual(nameOf('a-b.example.test'), nameOf('a.b-example.test'));
  for (const bad of ['http://169.254.169.254:80', '169.254.0.1:80', 'http://[fe80::1]:80', 'http://[febf::1]:80', 'http://[fd00:ec2::254]:80', '[fd00:ec2::254]:80', 'http://[::ffff:169.254.169.254]:80']) {
    assert.equal(validOrigin(bad), null, bad);
    assert.match(originError(bad), /Link-local/, bad);
  }
  assert.equal(originError('127.0.0.1:80'), null);
  assert.match(docker, /^umask 077; docker pull/);
  assert.doesNotMatch(docker, /\$/);
  // Server twin and browser builder produce identical Docker output.
  const full = { ...env, AGENT_LOCAL_UPSTREAM: 'http://127.0.0.1:1' };
  const { connectionCommand } = await import('../public/js/agent-view.js');
  const browser = connectionCommand(full, 'docker', 'https://portal.example.test');
  assert.equal(docker, browser);
});

test('tokens end when the hostname leaves the account or the issuer resets their password, and a failed rotate does not burn them', async (t) => {
  const { f, a } = await ready(t);
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const issue = async () => (await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).data.token;
  const post = (token) => request(f.port, '/api/connect/v1/command', { method: 'POST', headers: { ...bearer(token), 'content-type': 'application/json' }, body: JSON.stringify({ origin: '127.0.0.1:3000' }) });
  const token = await issue();
  const rotate = f.edge.rotateCredential;
  f.edge.rotateCredential = async () => { throw Object.assign(new Error('internal_error'), { code: 'internal_error' }); };
  assert.equal((await post(token)).status, 500);
  f.edge.rotateCredential = rotate;
  assert.equal((await post(token)).status, 200, 'token still usable after a failed rotate');
  const detached = await issue();
  f.records.delete(`${tids[0]}:app.example.test`);
  assert.equal((await request(f.port, '/api/connect/v1/hostname', { headers: bearer(detached) })).status, 401, 'edge-side detach ends the token');
  await a.client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const beforeReset = await issue();
  const accounts = f.store.read('accounts', {});
  accounts.users[0].auth_version += 1;
  f.store.write('accounts', accounts);
  assert.equal((await request(f.port, '/api/connect/v1/hostname', { headers: bearer(beforeReset) })).status, 401);
});

test('server command uses the same pinned agent image as the browser', async () => {
  const { AGENT_IMAGE } = await import('../src/connect-command.js');
  const { readFileSync } = await import('node:fs');
  const browserSource = readFileSync(new URL('../public/js/agent-view.js', import.meta.url), 'utf8');
  assert.ok(browserSource.includes(`'${AGENT_IMAGE}'`));
  assert.match(AGENT_IMAGE, /@sha256:[a-f0-9]{64}$/);
});

test('failed rotations spend budget without burning the token, and re-added hostnames end old tokens', async (t) => {
  const { f, a } = await ready(t);
  await a.client.call('/api/hostnames/app.example.test/verify', 'POST');
  const token = (await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).data.token;
  const post = () => request(f.port, '/api/connect/v1/command', { method: 'POST', headers: { ...bearer(token), 'content-type': 'application/json' }, body: JSON.stringify({ origin: '127.0.0.1:3000' }) });
  const rotate = f.edge.rotateCredential;
  f.edge.rotateCredential = async () => { throw Object.assign(new Error('internal_error'), { code: 'internal_error' }); };
  assert.equal((await post()).status, 500);
  assert.equal((await post()).status, 500, 'a failed rotate leaves the token usable');
  f.edge.rotateCredential = rotate;
  assert.equal((await post()).status, 200, 'third attempt fits the 3/day token budget');
  const next = (await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).data.token;
  const again = await request(f.port, '/api/connect/v1/command', { method: 'POST', headers: { ...bearer(next), 'content-type': 'application/json' }, body: JSON.stringify({ origin: '127.0.0.1:3000' }) });
  assert.equal(again.status, 429, 'attempts that reached the edge spent the budget');
  const reuse = await request(f.port, '/api/connect/v1/hostname', { headers: bearer(next) });
  assert.equal(reuse.data.command_issued, false, 'a budget refusal does not burn the token');
  const old = (await a.client.call('/api/hostnames/app.example.test/connect-token', 'POST')).data.token;
  f.records.get(`${tids[0]}:app.example.test`).created_at = new Date(1000).toISOString();
  assert.equal((await request(f.port, '/api/connect/v1/hostname', { headers: bearer(old) })).status, 401);
});
