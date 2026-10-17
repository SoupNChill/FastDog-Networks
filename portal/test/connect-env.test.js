import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, request } from './helpers.js';
import { AGENT_IMAGE, agentSuffix, dockerDetails, dockerRun, serializeDockerEnv, buildCommand } from '../src/connect-command.js';

const host = 'app.example.test';
const origin = 'http://127.0.0.1:3000';
const keys = ['AGENT_TOKEN', 'AGENT_HOSTNAME', 'AGENT_NAME', 'EDGE_HTTP_URL', 'EDGE_WS_URL', 'AGENT_LOCAL_UPSTREAM'];

test('Docker template is secret-free and env serialization is literal and rejects line injection', () => {
  const run = dockerRun(host);
  assert.equal(run, `docker run -d --name fastdog-agent-${agentSuffix(host)} --network host --cap-drop ALL --security-opt no-new-privileges --restart unless-stopped --env-file ENV_FILE ${AGENT_IMAGE}`);
  assert.match(run, /^[a-zA-Z0-9 /:@._-]+$/);
  assert.equal(dockerRun(host, '/home/user/app.env'), run.replace('ENV_FILE', '/home/user/app.env'));
  for (const path of ['x', '/tmp/a b', '/tmp/a;id', '/tmp/$x', '/tmp/a\n']) assert.throws(() => dockerRun(host, path));
  const env = { AGENT_TOKEN: 'fake-secret', AGENT_HOSTNAME: host, AGENT_NAME: 'literal "name"=value', EDGE_HTTP_URL: 'https://edge.example.test' };
  const text = serializeDockerEnv(env, origin);
  assert.equal(text, `AGENT_TOKEN=fake-secret\nAGENT_HOSTNAME=${host}\nAGENT_NAME=literal "name"=value\nEDGE_HTTP_URL=https://edge.example.test\nEDGE_WS_URL=wss://edge.example.test/_fastdog/tunnel\nAGENT_LOCAL_UPSTREAM=${origin}\n`);
  assert.ok(buildCommand(env, { platform: 'docker', origin }).includes("'AGENT_NAME=literal \"name\"=value'"));
  for (const key of keys.filter((key) => key !== 'AGENT_LOCAL_UPSTREAM')) {
    for (const bad of ['bad\nINJECT=value', 'bad\0value', 'bad\rvalue']) {
      assert.equal(serializeDockerEnv({ ...env, [key]: bad }, origin), null);
      assert.equal(buildCommand({ ...env, [key]: bad }, { platform: 'docker', origin }), null);
    }
  }
});

for (const mode of ['key', 'token']) test(`${mode}: env issuance shares JSON budgets, validation, rotation and redacted logs`, async (t) => {
  const logs = [];
  const f = await fixture(t, { edgeUrl: 'https://edge.example.test', logger: (line) => logs.push(line) });
  const a = await f.seed();
  const key = (await a.client.call('/api/keys', 'POST', { password: a.password, scopes: ['hostnames:create', 'status:read', 'connect'] })).data.key;
  const call = (secret, path, method = 'GET', body) => request(f.port, path, { method, headers: { authorization: `Bearer ${secret}`, 'content-type': 'application/json' }, body });
  const made = await call(key, '/api/v1/hostnames', 'POST', { hostname: host });
  assert.deepEqual(made.data.docker, dockerDetails(host));
  assert.deepEqual((await call(key, `/api/v1/hostnames/${host}`)).data.docker, made.data.docker);
  await a.client.call(`/api/hostnames/${host}/verify`, 'POST');
  const secrets = [key];
  const issue = async () => {
    if (mode === 'key') return key;
    const token = (await a.client.call(`/api/hostnames/${host}/connect-token`, 'POST')).data.token;
    secrets.push(token);
    assert.deepEqual((await call(token, '/api/connect/v1/hostname')).data.docker, made.data.docker);
    return token;
  };
  const path = mode === 'key' ? `/api/v1/hostnames/${host}/connect` : '/api/connect/v1/command';
  let secret = await issue();
  const post = (body) => call(secret, path, 'POST', { origin, platform: 'docker', ...body });
  for (const body of [{ platform: 'linux', format: 'env' }, { format: null }, { format: 'other' }]) {
    const bad = await post(body);
    assert.equal(bad.status, 400);
    assert.equal(bad.data.error, 'invalid_format');
    assert.match(bad.headers['content-type'], /application\/json/);
  }
  const env = await post({ format: 'env' });
  assert.equal(env.status, 200);
  assert.equal(env.headers['content-type'], 'text/plain; charset=utf-8');
  assert.equal(env.headers['cache-control'], 'no-store');
  assert.ok(env.text.endsWith('\n'));
  assert.deepEqual(env.text.trimEnd().split('\n').map((line) => line.split('=')[0]), keys);
  const tokenValue = env.text.split('\n')[0].slice('AGENT_TOKEN='.length);
  secrets.push(tokenValue);
  if (mode === 'token') {
    const used = await post({ format: 'json' });
    assert.equal(used.status, 409);
    assert.equal(used.data.error, 'token_used');
  }
  secret = await issue();
  assert.equal((await post({ format: 'json' })).status, 200);
  secret = await issue();
  assert.equal((await post({ format: 'env' })).status, 200);
  secret = await issue();
  assert.equal((await post({ format: 'json' })).status, 429);
  assert.equal(f.calls.filter(([name]) => name === 'rotate').length, 3);
  f.advance(86400001);
  secret = await issue();
  const rotate = f.edge.rotateCredential;
  f.edge.rotateCredential = async (...args) => {
    const result = await rotate(...args);
    result.credential.agent_env.AGENT_NAME = 'unsafe\nINJECT=value';
    return result;
  };
  const unsafe = await post({ format: 'env' });
  assert.equal(unsafe.status, 500);
  assert.equal(unsafe.data.error, 'internal_error');
  assert.match(unsafe.headers['content-type'], /application\/json/);
  assert.doesNotMatch(unsafe.text, /INJECT|AGENT_TOKEN/);
  assert.ok(logs.length > 0);
  const allLogs = JSON.stringify([logs, f.store.read('api_key_audit', [])]);
  for (const value of secrets) assert.ok(!allLogs.includes(value));
  assert.doesNotMatch(allLogs, /fdct_|fdak_|fake-|AGENT_TOKEN/);
});
