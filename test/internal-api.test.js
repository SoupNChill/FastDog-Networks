import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { createInternalServer, assertLoopbackBind } from '../src/internal/server.js';
import { readJson, writeJson } from '../src/onboard/json.js';
import { validCredential, issueCredential } from '../src/onboard/credentials.js';
import { registerAgent, getAgentByHost, attachWs, closeHost, _resetForTests } from '../src/control/tunnels.js';
import { checkDnsVerification } from '../src/onboard/attach.js';

const tid = 't_aaaaaaaaaaaaaaaaaaaa';
const other = 't_bbbbbbbbbbbbbbbbbbbb';
const target = 'attach.example-edge.test';
const fake = () => `fake-${randomBytes(32).toString('hex')}`;
const missing = () => { throw Object.assign(new Error('no record'), { code: 'ENODATA' }); };
const prefix = (tenant = tid) => `/internal/v1/tenants/${tenant}/hostnames`;

async function setup(t, extra = {}) {
  const directory = fs.mkdtempSync(path.join(process.cwd(), 'test/.internal-'));
  let time = Date.UTC(2026, 0, 1);
  const portalKey = fake();
  const agentToken = fake();
  const txt = new Map();
  const closed = [];
  const logs = [];
  const calls = { cname: 0, a: 0, txt: 0 };
  const resolver = {
    async resolveCname() { calls.cname++; return [target]; },
    async resolve4() { calls.a++; return []; },
    async resolveTxt(name) { calls.txt++; return txt.get(name) ?? []; },
  };
  const registry = { getAgentByHost, closeHost(host) { closed.push(host); closeHost(host); } };
  const server = createInternalServer({ tlsAskEnabled: true, dataDir: directory, portalKey, agentToken, attachTarget: target,
    altAttachTarget: 'edge.example.test', edgePublicIp: '192.0.2.1', reservedSuffixes: [],
    resolver, registry, now: () => time, logger: (event) => logs.push(event), ...extra });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    _resetForTests();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const port = server.address().port;
  function request(url, method = 'GET', body, key = portalKey, headers = {}) {
    return new Promise((resolve, reject) => {
      const data = body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body);
      const req = http.request({ host: '127.0.0.1', port, path: url, method, headers: {
        ...(key ? { 'x-fastdog-portal-key': key } : {}), ...(data ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {}), ...headers,
      } }, (res) => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { raw += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, body: raw ? JSON.parse(raw) : null, raw, headers: res.headers }));
      });
      req.on('error', reject);
      req.end(data);
    });
  }
  async function claim(host = 'app.example.com', tenant = tid, limit = 3) {
    const result = await request(prefix(tenant), 'POST', { hostname: host, hostname_limit: limit });
    assert.equal(result.status, 201);
    return result.body;
  }
  async function activate(host = 'app.example.com', tenant = tid) {
    const c = await claim(host, tenant);
    txt.set(c.dns.txt.name, [[c.dns.txt.value]]);
    const result = await request(`${prefix(tenant)}/${host}/verify`, 'POST');
    assert.equal(result.status, 200);
    assert.equal(result.body.verified, true);
    return result.body;
  }
  return { directory, server, portalKey, agentToken, resolver, txt, closed, calls, logs, port, request, claim, activate,
    advance(ms) { time += ms; } };
}

test('factory rejects missing, short and operator-equal keys and non-loopback binds', () => {
  const key = fake();
  for (const portalKey of [undefined, '', 'fake-short', key]) assert.throws(() => createInternalServer({ portalKey, agentToken: key }), /PORTAL_KEY/);
  for (const address of ['0.0.0.0', '::', 'localhost', '192.0.2.1']) assert.throws(() => assertLoopbackBind(address), /loopback/);
  for (const address of ['127.0.0.1', '127.0.0.2', '::1']) assert.equal(assertLoopbackBind(address), address);
});

test('auth, routing, methods, body limits and safe logs', async (t) => {
  const f = await setup(t);
  assert.equal((await f.request('/health', 'GET', undefined, null)).status, 200);
  assert.equal((await f.request('/internal/v1/health', 'GET', undefined, null)).body.ok, true);
  for (const key of [null, fake(), f.agentToken]) assert.deepEqual((await f.request(prefix(), 'GET', undefined, key)).body, { error: 'unauthorized' });
  assert.equal((await f.request(prefix(), 'GET', undefined, null, { 'x-fastdog-token': f.portalKey })).status, 401);
  assert.deepEqual((await f.request('/internal/v1/missing')).body, { error: 'not_found' });
  assert.equal((await f.request(prefix(), 'PUT')).status, 405);
  assert.equal((await f.request('/health', 'POST')).status, 405);
  assert.equal((await f.request(prefix('invalid'))).body.error, 'invalid_tenant');
  for (const body of ['{', '[]', 'null', '42']) assert.equal((await f.request(prefix(), 'POST', body)).body.error, 'invalid_json');
  assert.equal((await f.request(prefix(), 'POST', 'x'.repeat(16385))).status, 413);
  assert.equal((await f.request(prefix(), 'POST', { hostname: 'app.example.com', hostname_limit: 0 })).body.error, 'invalid_limit');
  await f.request(`${prefix()}?token=fake-query`, 'POST', { hostname: 'app.example.com', hostname_limit: 1 });
  assert.equal(f.server.requestTimeout, 5000);
  assert.equal(f.server.headersTimeout, 5000);
  const logs = JSON.stringify(f.logs);
  for (const forbidden of [tid, f.portalKey, 'app.example.com', 'fake-query', 'fd-verify=']) assert.ok(!logs.includes(forbidden));
});

test('pending claims normalize, expire, respect limits and remain isolated', async (t) => {
  const f = await setup(t);
  const c = await f.claim(' App.Example.COM. ', tid, 1);
  assert.equal(c.hostname, 'app.example.com');
  assert.match(c.dns.txt.value, /^fd-verify=[a-f0-9]{32}$/);
  assert.equal(Date.parse(c.expires_at) - Date.parse(c.created_at), 86400000);
  const again = await f.request(prefix(), 'POST', { hostname: c.hostname, hostname_limit: 1 });
  assert.equal(again.status, 200);
  assert.deepEqual(again.body, c);
  assert.equal((await f.request(prefix(), 'POST', { hostname: 'myapp.example.com', hostname_limit: 1 })).body.error, 'hostname_limit_reached');
  for (const [method, suffix] of [['GET', ''], ['POST', '/verify'], ['POST', '/credentials/rotate'], ['GET', '/agent'], ['DELETE', '']]) {
    assert.deepEqual((await f.request(`${prefix(other)}/app.example.com${suffix}`, method)).body, { error: 'hostname_not_found' });
  }
  assert.equal((await f.request(`${prefix()}/app.example.com/agent`)).body.error, 'not_active');
  assert.equal((await f.request(`${prefix()}/app.example.com/credentials/rotate`, 'POST')).body.error, 'not_active');
  assert.equal((await f.request('/tls/ask?domain=app.example.com')).status, 404);
  f.advance(86400000);
  assert.deepEqual((await f.request(prefix())).body, { hostnames: [] });
  assert.equal((await f.request(`${prefix()}/app.example.com`)).status, 404);
  const renewed = await f.claim('app.example.com', tid, 1);
  assert.notEqual(renewed.dns.txt.value, c.dns.txt.value);
  assert.equal(fs.statSync(path.join(f.directory, 'tenant_hostnames.json')).mode & 0o777, 0o600);
});

test('activation requires exact TXT and routing proofs and issues only once', async (t) => {
  const f = await setup(t);
  const c = await f.claim();
  const url = `${prefix()}/app.example.com/verify`;
  let result = await f.request(url, 'POST');
  assert.equal(result.body.checks.routing.ok, true);
  assert.equal(result.body.checks.ownership.error, 'txt_not_found');
  f.txt.set(c.dns.txt.name, [[`${c.dns.txt.value}extra`]]);
  result = await f.request(url, 'POST');
  assert.equal(result.body.checks.ownership.error, 'txt_mismatch');
  f.txt.set(c.dns.txt.name, [[c.dns.txt.value.slice(0, 9), c.dns.txt.value.slice(9)]]);
  f.resolver.resolveCname = async () => ['other.example.test'];
  result = await f.request(url, 'POST');
  assert.equal(result.body.verified, false);
  assert.equal(result.body.checks.routing.error, 'cname_wrong_target');
  f.resolver.resolveCname = async () => [target];
  let changes = 0;
  f.server.on('routesChanged', () => changes++);
  result = await f.request(url, 'POST');
  const credential = result.body.credential;
  assert.equal(result.body.status, 'active');
  assert.match(credential.token, /^[a-f0-9]{64}$/);
  assert.deepEqual(credential.agent_env, { AGENT_TOKEN: credential.token, AGENT_HOSTNAME: c.hostname, AGENT_NAME: c.hostname });
  assert.equal(validCredential(credential.token, c.hostname, f.directory), true);
  assert.equal(validCredential(credential.token, 'myapp.example.com', f.directory), false);
  assert.equal(changes, 1);
  const before = f.calls.txt;
  result = await f.request(url, 'POST');
  assert.equal(result.body.credential, undefined);
  assert.equal(f.calls.txt, before);
  const active = await f.request(`${prefix()}/app.example.com`);
  assert.equal(active.body.expires_at, undefined);
  assert.ok(!JSON.stringify(active.body).includes(c.dns.txt.value));
  assert.ok(!JSON.stringify((await f.request(prefix())).body).includes(credential.token));
  const stored = fs.readFileSync(path.join(f.directory, 'agent-credentials.json'), 'utf8');
  assert.ok(!stored.includes(credential.token));
  assert.ok(JSON.parse(stored)[0].last_used_at);
  assert.equal((await f.request('/tls/ask?domain=APP.EXAMPLE.COM.')).status, 404);
  assert.equal((await f.request('/tls/ask?domain=app.example.com', 'GET', undefined, null, { 'x-forwarded-for': '192.0.2.1' })).status, 404);
});

test('first active owner wins races; deleting a losing claim preserves the winner', async (t) => {
  const f = await setup(t);
  const a = await f.claim();
  const b = await f.claim('app.example.com', other);
  f.txt.set(a.dns.txt.name, [[a.dns.txt.value], [b.dns.txt.value]]);
  const results = await Promise.all([tid, other].map((tenant) => f.request(`${prefix(tenant)}/app.example.com/verify`, 'POST')));
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 409]);
  const winner = results[0].status === 200 ? tid : other;
  const loser = winner === tid ? other : tid;
  assert.equal(readJson('agent-credentials.json', [], f.directory).length, 1);
  assert.equal(fs.statSync(path.join(f.directory, 'agent-credentials.json')).mode & 0o777, 0o600);
  assert.equal((await f.request(`${prefix(loser)}/app.example.com/verify`, 'POST')).body.error, 'hostname_unavailable');
  await f.request(`${prefix(loser)}/app.example.com`, 'DELETE');
  assert.deepEqual(readJson('tunnel_hosts.json', [], f.directory), ['app.example.com']);
  assert.equal((await f.request(`${prefix(winner)}/app.example.com`)).body.status, 'active');
});

test('same claim verified concurrently returns exactly one credential', async (t) => {
  const f = await setup(t);
  const c = await f.claim();
  f.txt.set(c.dns.txt.name, [[c.dns.txt.value]]);
  const results = await Promise.all([1, 2].map(() => f.request(`${prefix()}/app.example.com/verify`, 'POST')));
  assert.ok(results.every((r) => r.status === 200));
  assert.equal(results.filter((r) => r.body.credential).length, 1);
});

test('rate limits, credential rotation, tenant registration, tunnel closure and detach', async (t) => {
  const f = await setup(t);
  const issued = await f.activate();
  const old = issued.credential.token;
  const reg = { hostname: 'app.example.com', localUpstream: 'http://127.0.0.1:9', expectedToken: f.agentToken, dataDir: f.directory };
  assert.throws(() => registerAgent({ ...reg, token: f.agentToken }), { status: 401 });
  const legacy = issueCredential({}, f.directory);
  assert.throws(() => registerAgent({ ...reg, token: legacy.token }), { status: 401 });
  assert.throws(() => registerAgent({ ...reg, token: f.portalKey }), { status: 401 });
  const registered = registerAgent({ ...reg, token: old });
  let terminated = false;
  assert.equal(attachWs(registered.id, { readyState: 1, terminate() { terminated = true; } }, old), true);
  assert.equal((await f.request(`${prefix()}/app.example.com/agent`)).body.connected, true);
  const rotated = await f.request(`${prefix()}/app.example.com/credentials/rotate`, 'POST');
  assert.equal(terminated, true);
  assert.equal(getAgentByHost('app.example.com'), null);
  assert.equal(attachWs(registered.id, {}, old), false);
  assert.equal(validCredential(old, 'app.example.com', f.directory), false);
  assert.equal(validCredential(rotated.body.credential.token, 'app.example.com', f.directory), true);
  assert.equal(readJson('agent-credentials.json', [], f.directory).find((r) => r.id === issued.credential.id).revoked_at !== null, true);
  for (let i = 0; i < 4; i++) assert.equal((await f.request(`${prefix()}/app.example.com/credentials/rotate`, 'POST')).status, 200);
  assert.equal((await f.request(`${prefix()}/app.example.com/credentials/rotate`, 'POST')).status, 429);
  for (let i = 0; i < 5; i++) assert.equal((await f.request(`${prefix()}/app.example.com/verify`, 'POST')).status, 200);
  let limited = await f.request(`${prefix()}/app.example.com/verify`, 'POST');
  assert.equal(limited.status, 429);
  assert.equal(limited.body.retry_after, 60);
  assert.equal(limited.headers['retry-after'], '60');
  f.advance(86400000);
  assert.equal((await f.request(`${prefix()}/app.example.com/verify`, 'POST')).status, 200);
  assert.equal((await f.request(`${prefix()}/app.example.com/credentials/rotate`, 'POST')).status, 200);
  assert.equal((await f.request(`${prefix()}/app.example.com`, 'DELETE')).body.detached, true);
  assert.equal((await f.request(`${prefix()}/app.example.com`, 'DELETE')).body.error, 'hostname_not_found');
  assert.deepEqual(readJson('tunnel_hosts.json', [], f.directory), []);
  assert.ok(readJson('agent-credentials.json', [], f.directory).every((r) => r.tenant_id !== tid));
  assert.equal((await f.request('/tls/ask?domain=app.example.com')).status, 404);
});

test('legacy attachments are protected and only active legacy hosts pass TLS ask', async (t) => {
  const f = await setup(t);
  writeJson('attached_hosts.json', [{ hostname: 'legacy.example.com', status: 'active' }, { hostname: 'pending.example.com', status: 'pending' }], 0o600, f.directory);
  for (const host of ['legacy.example.com', 'pending.example.com']) {
    assert.equal((await f.request(prefix(), 'POST', { hostname: host, hostname_limit: 3 })).body.error, 'hostname_unavailable');
    assert.equal((await f.request(`${prefix()}/${host}`, 'DELETE')).body.error, 'hostname_not_found');
  }
  assert.equal((await f.request('/tls/ask?domain=legacy.example.com')).raw, '');
  assert.equal((await f.request('/tls/ask?domain=legacy.example.com')).status, 200);
  assert.equal((await f.request('/tls/ask?domain=pending.example.com')).status, 404);
  assert.ok(registerAgent({ hostname: 'legacy.example.com', localUpstream: 'http://127.0.0.1:9', expectedToken: f.agentToken, token: f.agentToken, dataDir: f.directory }).id);
});

test('reserved names apply before creation and explicit overrides allow synthetic hosts', async (t) => {
  const f = await setup(t, { reservedSuffixes: ['reserved.example.com', 'test'] });
  for (const host of ['reserved.example.com', 'x.reserved.example.com', 'app.example.test', target]) {
    assert.equal((await f.request(prefix(), 'POST', { hostname: host, hostname_limit: 3 })).body.error, 'reserved_hostname');
  }
  await f.claim('app.example.com');
});

test('DNS chain limit is five links and A fallback is injected', async () => {
  let hops;
  let maximum;
  const resolver = { async resolveCname() { hops++; return [hops === maximum ? target : `hop${hops}.example.com`]; }, async resolve4() { return ['192.0.2.1']; } };
  const opts = { resolver, attachTarget: target, altAttachTarget: '', edgePublicIp: '192.0.2.1' };
  hops = 0; maximum = 5;
  assert.equal((await checkDnsVerification('app.example.com', opts)).verified, true);
  assert.equal(hops, 5);
  hops = 0; maximum = 6;
  assert.equal((await checkDnsVerification('app.example.com', opts)).verified, false);
  assert.equal(hops, 5);
  resolver.resolveCname = missing;
  assert.equal((await checkDnsVerification('app.example.com', opts)).method, 'a_record');
  resolver.resolve4 = async () => ['192.0.2.2'];
  assert.equal((await checkDnsVerification('app.example.com', opts)).error, 'a_wrong_target');
  resolver.resolve4 = missing;
  assert.equal((await checkDnsVerification('app.example.com', opts)).error, 'no_dns_record');
});

test('DNS timeout is bounded and a deleted in-flight claim cannot activate', async (t) => {
  const f = await setup(t);
  const c = await f.claim();
  f.txt.set(c.dns.txt.name, [[c.dns.txt.value]]);
  f.resolver.resolveCname = () => new Promise(() => {});
  const started = Date.now();
  const result = await f.request(`${prefix()}/app.example.com/verify`, 'POST');
  assert.equal(result.body.checks.routing.error, 'dns_timeout');
  assert.ok(Date.now() - started < 5000);
  let release;
  let entered;
  const ready = new Promise((resolve) => { entered = resolve; });
  f.resolver.resolveCname = () => new Promise((resolve) => { release = resolve; entered(); });
  const verifying = f.request(`${prefix()}/app.example.com/verify`, 'POST');
  await ready;
  await f.request(`${prefix()}/app.example.com`, 'DELETE');
  release([target]);
  assert.equal((await verifying).body.error, 'hostname_not_found');
  assert.deepEqual(readJson('tunnel_hosts.json', [], f.directory), []);
});

test('incomplete request is terminated within five seconds', async (t) => {
  const f = await setup(t);
  const started = Date.now();
  const status = await new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: f.port, path: prefix(), method: 'POST', headers: {
      'x-fastdog-portal-key': f.portalKey, 'content-length': 100,
    } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(0));
    req.write('{');
  });
  assert.ok([0, 400, 408].includes(status));
  assert.ok(Date.now() - started < 6500);
});

test('INTERNAL_TIMEOUT_CODES off keeps 400 invalid_json; on returns 408 for a stalled body and 504 for a stalled handler', async (t) => {
  let hang;
  const siteProbes = { testSite: () => new Promise((resolve) => { hang = resolve; }) };
  const legacy = await setup(t);
  const f = await setup(t, { timeoutCodes: true, siteProbes });
  await f.activate();
  const stalledBody = (fixture) => new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: fixture.port, path: prefix(), method: 'POST', headers: {
      'x-fastdog-portal-key': fixture.portalKey, 'content-length': 100,
    } }, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: raw ? JSON.parse(raw) : null }));
    });
    req.on('error', () => resolve({ status: 0 }));
    req.write('{');
  });
  const started = Date.now();
  const [off, body, handler] = await Promise.all([stalledBody(legacy), stalledBody(f),
    f.request(`${prefix()}/app.example.com/test`, 'POST')]);
  hang?.({ ok: true });
  assert.deepEqual(off, { status: 400, body: { error: 'invalid_json' } });
  assert.deepEqual(body, { status: 408, body: { error: 'request_timeout' } });
  assert.equal(handler.status, 504);
  assert.deepEqual(handler.body, { error: 'gateway_timeout' });
  assert.ok(Date.now() - started < 6500);
});


test('chunked body limit and exact 16 KiB boundary', async (t) => {
  const f = await setup(t);
  const base = JSON.stringify({ hostname: 'app.example.com', hostname_limit: 1 });
  assert.equal((await f.request(prefix(), 'POST', base.padEnd(16384, ' '))).status, 201);
  const result = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: f.port, path: prefix(), method: 'POST',
      headers: { 'x-fastdog-portal-key': f.portalKey, 'transfer-encoding': 'chunked' } }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(data) }));
    });
    req.on('error', reject);
    req.write('x'.repeat(8192));
    req.end('x'.repeat(8193));
  });
  assert.equal(result.status, 413);
  assert.deepEqual(result.body, { error: 'payload_too_large' });
});

test('verify allowance is shared across hosts of one tenant and independent for another', async (t) => {
  const f = await setup(t);
  await f.claim('app.example.com');
  await f.claim('myapp.example.com');
  await f.claim('x.app.example.com', other);
  for (let i = 0; i < 6; i++) {
    assert.equal((await f.request(`${prefix()}/${i % 2 ? 'myapp' : 'app'}.example.com/verify`, 'POST')).status, 200);
  }
  assert.equal((await f.request(`${prefix()}/myapp.example.com/verify`, 'POST')).status, 429);
  assert.equal((await f.request(`${prefix(other)}/x.app.example.com/verify`, 'POST')).status, 200);
  assert.equal(f.calls.txt, 7);
  f.advance(60000);
  assert.equal((await f.request(`${prefix()}/app.example.com/verify`, 'POST')).status, 200);
});

test('TLS ask logs contain status and an aggregate reason only; missing domains fail closed', async (t) => {
  const f = await setup(t);
  for (const suffix of ['', '?domain=127.0.0.1', '?domain=*.example.com', '?domain=app.example.com']) {
    assert.equal((await f.request(`/tls/ask${suffix}`)).status, 404);
  }
  assert.ok(f.logs.every((entry) => Object.keys(entry).every((key) => ['status', 'reason'].includes(key)) && entry.status === 404));
  assert.ok(!JSON.stringify(f.logs).includes('example.com'));
});
