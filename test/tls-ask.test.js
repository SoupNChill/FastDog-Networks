import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs, { readFileSync } from 'node:fs';
import { createInternalServer } from '../src/internal/server.js';
import { createClaims } from '../src/internal/claims.js';
import { createTlsAsk, registeredDomain } from '../src/internal/tls-ask.js';
import { writeJson } from '../src/onboard/json.js';
import { tempDir } from './helpers/temp-dir.js';

const TENANT_A = 't_aaaaaaaaaaaaaaaaaaaa';
const TENANT_B = 't_bbbbbbbbbbbbbbbbbbbb';

function setup(t, overrides = {}) {
  let time = Date.UTC(2026, 0, 1);
  const directory = tempDir(t);
  const logs = [];
  const server = createInternalServer({
    portalKey: 'synthetic-portal-key-'.repeat(3), agentToken: 'synthetic-agent-key',
    dataDir: directory, tlsAskEnabled: true, liveVerify: false, now: () => time,
    attachTarget: 'attach.example.test', altAttachTarget: 'edge.example.test',
    reservedSuffixes: ['reserved.example.test'], logger: (event) => logs.push(event), ...overrides,
  });
  const save = (records, file = 'tenant_hostnames.json') => writeJson(file, records, 0o600, directory);
  const claim = (hostname, extra = {}) => ({ hostname, tenant_id: TENANT_A,
    status: 'active', verified_at: new Date(time).toISOString(), ...extra });
  // Exercise the real handler without opening sockets or making network calls.
  async function ask(domain = 'app.example.test', { address = '127.0.0.1', headers = {}, method = 'GET', prefix = '' } = {}) {
    const req = new EventEmitter();
    Object.assign(req, { url: `${prefix}/tls/ask?domain=${encodeURIComponent(domain)}`, method,
      headers, socket: { remoteAddress: address } });
    const res = new EventEmitter();
    res.writeHead = (status, headers) => Object.assign(res, { statusCode: status, headers });
    res.end = (body) => { Object.assign(res, { body, writableEnded: true, writableFinished: true }); res.emit('finish'); };
    server.emit('request', req, res);
    for (let i = 0; i < 50 && !res.writableEnded; i++) await new Promise((resolve) => { setImmediate(resolve); });
    assert.equal(res.writableEnded, true);
    return res;
  }
  const status = async (domain, options) => (await ask(domain, options)).statusCode;
  return { ask, status, save, claim, logs, directory, advance: (ms = 60000) => { time += ms; } };
}

// Direct function harness for budget rules (no HTTP layer).
function direct(t, options = {}) {
  let time = Date.UTC(2026, 0, 1);
  const directory = tempDir(t);
  const ask = createTlsAsk({ dataDir: directory, tlsAskEnabled: true, liveVerify: false, now: () => time,
    attachTarget: 'attach.example.test', altAttachTarget: 'edge.example.test',
    reservedSuffixes: ['reserved.example.test'], ...options });
  const save = (records, file = 'tenant_hostnames.json') => writeJson(file, records, 0o600, directory);
  const claim = (hostname, tenant = TENANT_A, extra = {}) => ({ hostname, tenant_id: tenant, status: 'active',
    verified_at: new Date(time).toISOString(), ...extra });
  return { ask, save, claim, directory, advance: (ms = 60000) => { time += ms; } };
}

test('TLS ask defaults off; only TLS_ASK_ENABLED=1 enables the environment flag', async (t) => {
  const previous = process.env.TLS_ASK_ENABLED;
  t.after(() => { if (previous === undefined) delete process.env.TLS_ASK_ENABLED; else process.env.TLS_ASK_ENABLED = previous; });
  for (const value of [undefined, '0', 'true', '1']) {
    if (value === undefined) delete process.env.TLS_ASK_ENABLED; else process.env.TLS_ASK_ENABLED = value;
    const h = setup(t, { tlsAskEnabled: undefined });
    h.save([h.claim('app.example.test')]);
    assert.equal((await h.ask()).statusCode, value === '1' ? 200 : 404);
    if (value !== '1') assert.equal((await h.ask(undefined, { method: 'POST' })).statusCode, 404);
  }
});

test('TLS ask normalizes verified active claims and observes revocation immediately', async (t) => {
  const h = setup(t);
  h.save([h.claim('app.example.test'), h.claim('xn--bcher-kva.example.test')]);
  for (const domain of [' APP.EXAMPLE.TEST. ', 'bücher.example.test']) {
    const response = await h.ask(domain, { prefix: '/internal/v1' });
    assert.equal(response.statusCode, 200);
    assert.equal(response.body, '');
  }
  h.save([]);
  assert.equal((await h.ask()).statusCode, 404);
  assert.deepEqual(h.logs, [{ status: 200, reason: 'approved_new' }, { status: 200, reason: 'approved_new' },
    { status: 404, reason: 'denied' }]);
});

test('TLS ask denies pending, expired, unverified, reserved and malformed hostnames', async (t) => {
  const h = setup(t);
  h.save([
    h.claim('pending.example.test', { status: 'pending' }),
    h.claim('expired.example.test', { status: 'expired', expires_at: '2025-01-01T00:00:00Z' }),
    h.claim('unverified.example.test', { verified_at: null }),
    h.claim('reserved.example.test'), h.claim('sub.reserved.example.test'), h.claim('attach.example.test'),
  ]);
  h.save(['pending.example.test', 'expired.example.test', 'unknown.example.test'], 'tunnel_hosts.json');
  for (const host of ['pending.example.test', 'expired.example.test', 'unverified.example.test',
    'reserved.example.test', 'sub.reserved.example.test', 'attach.example.test', 'unknown.example.test',
    '127.0.0.1', '[::1]', '*.example.test', 'app.example.test:443', 'app.example.test/path', '']) {
    assert.equal((await h.ask(host)).statusCode, 404, host);
  }
});

test('TLS ask permits only explicit active operator legacy attachments', async (t) => {
  const h = setup(t);
  h.save([{ hostname: 'legacy.example.test', status: 'active' },
    { hostname: 'pending.example.test', status: 'pending' },
    { hostname: 'tenant.example.test', status: 'active', tenant_id: TENANT_A }], 'attached_hosts.json');
  assert.equal((await h.ask('legacy.example.test')).statusCode, 200);
  for (const host of ['pending.example.test', 'tenant.example.test']) assert.equal((await h.ask(host)).statusCode, 404);
});

test('TLS ask rejects non-loopback and any forwarded header, including empty headers', async (t) => {
  const h = setup(t);
  h.save([h.claim('app.example.test')]);
  for (const address of ['192.0.2.1', '::ffff:192.0.2.1', '::2']) assert.equal((await h.ask(undefined, { address })).statusCode, 404);
  for (const name of ['forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto']) {
    for (const value of ['', '127.0.0.1']) assert.equal((await h.ask(undefined, { headers: { [name]: value } })).statusCode, 404);
  }
  for (const address of ['127.0.0.1', '::1', '::ffff:127.0.0.1']) assert.equal((await h.ask(undefined, { address })).statusCode, 200);
});

test('TLS ask approval set: static allow-list is normalized and the only way to approve reserved names', (t) => {
  const h = direct(t, { staticHosts: [' STATIC.Example.Test. ', 'reserved.example.test', 'bad host', ''] });
  h.save([h.claim('sub.reserved.example.test')]);
  assert.equal(h.ask('static.example.test').status, 200);
  assert.equal(h.ask('STATIC.EXAMPLE.TEST').status, 200);
  assert.equal(h.ask('reserved.example.test').status, 200);
  // Only the listed name, not its subdomains or an unlisted reserved name.
  assert.equal(h.ask('sub.reserved.example.test').status, 404);
  assert.equal(h.ask('attach.example.test').status, 404);
  assert.equal(h.ask('other.example.test').status, 404);
  assert.equal(direct(t).ask('static.example.test').status, 404, 'default list is empty');
});

test('TLS ask reads the static allow-list from TLS_ASK_STATIC_HOSTS', (t) => {
  const previous = process.env.TLS_ASK_STATIC_HOSTS;
  t.after(() => { if (previous === undefined) delete process.env.TLS_ASK_STATIC_HOSTS; else process.env.TLS_ASK_STATIC_HOSTS = previous; });
  process.env.TLS_ASK_STATIC_HOSTS = 'One.example.test, two.example.test.,,*.bad.test';
  const h = direct(t);
  assert.deepEqual(['one', 'two', 'three'].map((name) => h.ask(`${name}.example.test`).status), [200, 200, 404]);
  assert.equal(h.ask('bad.test').status, 404);
});

test('TLS ask approval set: tenant claims and legacy attachments approve, unverified claims do not', (t) => {
  const h = direct(t);
  h.save([h.claim('tenant.example.test'), h.claim('unverified.example.test', TENANT_A, { verified_at: null }),
    h.claim('pending.example.test', TENANT_A, { status: 'pending' })]);
  h.save([{ hostname: 'legacy.example.test', status: 'active' }], 'attached_hosts.json');
  assert.deepEqual(['tenant', 'legacy', 'unverified', 'pending', 'unknown'].map((n) => h.ask(`${n}.example.test`).status),
    [200, 200, 404, 404, 404]);
});

test('TLS ask per-tenant cap counts distinct hostnames and re-approves repeats for free', (t) => {
  const h = direct(t, { tenantMaxPerHour: 3 });
  const hosts = ['a', 'b', 'c', 'd'].map((n) => `${n}.example.test`);
  h.save([...hosts.map((host) => h.claim(host)), h.claim('other.example.test', TENANT_B)]);
  for (let i = 0; i < 10; i++) assert.equal(h.ask(hosts[0]).status, 200, 'retries do not burn budget');
  assert.equal(h.ask(hosts[1]).status, 200);
  assert.equal(h.ask(hosts[2]).status, 200);
  const capped = h.ask(hosts[3]);
  assert.equal(capped.status, 429);
  assert.equal(capped.retry_after, 3600);
  for (const host of hosts.slice(0, 3)) assert.equal(h.ask(host).status, 200, 'already approved hosts stay approved');
  assert.equal(h.ask('other.example.test').status, 200, 'other tenants have their own budget');
  h.advance(1800000);
  assert.equal(h.ask(hosts[3]).retry_after, 1800);
  h.advance(1800000);
  assert.equal(h.ask(hosts[3]).status, 200, 'budget returns after the window');
});

test('TLS ask per-tenant cap defaults to 10 and the env var overrides it', (t) => {
  const previous = process.env.TLS_ASK_TENANT_MAX_PER_HOUR;
  t.after(() => { if (previous === undefined) delete process.env.TLS_ASK_TENANT_MAX_PER_HOUR; else process.env.TLS_ASK_TENANT_MAX_PER_HOUR = previous; });
  delete process.env.TLS_ASK_TENANT_MAX_PER_HOUR;
  // Distinct registered domains so the per-domain cap does not interfere.
  const names = Array.from({ length: 12 }, (_, i) => `h${i}.site${i}.example.test`.replace('.example', ''));
  let h = direct(t);
  h.save(names.map((n) => h.claim(n)));
  assert.deepEqual(names.map((n) => h.ask(n).status), [...Array(10).fill(200), 429, 429]);
  process.env.TLS_ASK_TENANT_MAX_PER_HOUR = '2';
  h = direct(t);
  h.save(names.map((n) => h.claim(n)));
  assert.deepEqual(names.slice(0, 3).map((n) => h.ask(n).status), [200, 200, 429]);
});

test('TLS ask global approval cap returns 429 with retry_after and re-approves approved hosts', (t) => {
  const h = direct(t, { globalMaxPerHour: 2, tenantMaxPerHour: 50 });
  h.save([h.claim('a.example.test'), h.claim('b.example.test', TENANT_B), h.claim('c.example.test', 't_cccccccccccccccccccc')]);
  h.save([{ hostname: 'legacy.example.test', status: 'active' }], 'attached_hosts.json');
  assert.equal(h.ask('a.example.test').status, 200);
  h.advance(10000);
  assert.equal(h.ask('b.example.test').status, 200);
  for (const host of ['c.example.test', 'legacy.example.test']) {
    const capped = h.ask(host);
    assert.equal(capped.status, 429);
    assert.equal(capped.retry_after, 3590);
  }
  assert.equal(h.ask('a.example.test').status, 200);
  assert.equal(h.ask('b.example.test').status, 200);
  h.advance(3590000);
  assert.equal(h.ask('c.example.test').status, 200, 'oldest approval aged out');
});

test('TLS ask per-registered-domain cap counts distinct hostnames; repeats are free', (t) => {
  const previous = process.env.TLS_ASK_DOMAIN_MAX_PER_HOUR;
  t.after(() => { if (previous === undefined) delete process.env.TLS_ASK_DOMAIN_MAX_PER_HOUR; else process.env.TLS_ASK_DOMAIN_MAX_PER_HOUR = previous; });
  delete process.env.TLS_ASK_DOMAIN_MAX_PER_HOUR;
  const h = direct(t, { tenantMaxPerHour: 50 });
  const names = ['a', 'b', 'c', 'd', 'e', 'f'].map((n) => `${n}.example.test`);
  h.save([...names.map((host) => h.claim(host)), h.claim('x.other.test'), h.claim('y.example.test', TENANT_B)]);
  for (const host of names.slice(0, 5)) assert.equal(h.ask(host).status, 200);
  for (let i = 0; i < 5; i++) assert.equal(h.ask(names[0]).reason, 'approved_repeat');
  const capped = h.ask(names[5]);
  assert.deepEqual([capped.status, capped.reason, capped.retry_after], [429, 'approval_cap_domain', 3600]);
  assert.equal(h.ask('y.example.test').reason, 'approval_cap_domain', 'the cap spans tenants');
  assert.equal(h.ask('x.other.test').status, 200, 'other domains have their own budget');
  h.advance(3600000);
  assert.equal(h.ask(names[5]).status, 200, 'budget returns after the window');
  const small = direct(t, { domainMaxPerHour: 1 });
  small.save([small.claim('a.example.test'), small.claim('b.example.test')]);
  assert.deepEqual([small.ask('a.example.test').status, small.ask('b.example.test').status], [200, 429]);
});

test('TLS ask groups common second-level suffixes under two-letter TLDs as one registered domain', (t) => {
  const h = direct(t, { domainMaxPerHour: 1, tenantMaxPerHour: 50 });
  h.save(['a.example.co.uk', 'b.example.co.uk', 'a.other.co.uk', 'a.example.com', 'b.example.com', 'a.example.org.au', 'b.example.org.au',
    'a.example.co.example', 'b.example.co.example', 'a.example.uk', 'b.example.uk'].map((host) => h.claim(host)));
  const status = (host) => h.ask(host).status;
  assert.deepEqual(['a.example.co.uk', 'b.example.co.uk', 'a.other.co.uk'].map(status), [200, 429, 200]);
  assert.deepEqual(['a.example.com', 'b.example.com'].map(status), [200, 429], 'com under a long TLD is just a normal suffix');
  assert.deepEqual(['a.example.org.au', 'b.example.org.au'].map(status), [200, 429]);
  // A non two-letter TLD is not a public-suffix pair: the last two labels group.
  assert.deepEqual(['a.example.co.example', 'b.example.co.example'].map(status), [200, 429]);
  assert.deepEqual(['a.example.uk', 'b.example.uk'].map(status), [200, 429]);
  assert.deepEqual([registeredDomain('x.example.co.uk'), registeredDomain('example.co.uk'), registeredDomain('co.uk'),
    registeredDomain('a.b.example.test'), registeredDomain('example')], ['example.co.uk', 'example.co.uk', 'co.uk', 'example.test', 'example']);
});

test('TLS ask live verify re-confirms DNS proof before a first approval, with caching and fail-closed errors', async (t) => {
  const host = 'app.example.test';
  const txt = 'fd-verify=synthetic';
  const state = { calls: 0, proof: true, fail: null };
  const resolver = {
    async resolveCname() { state.calls++; if (state.fail) throw state.fail; return ['attach.example.test']; },
    async resolve4() { return []; },
    async resolveTxt() { if (state.fail) throw state.fail; return state.proof ? [[txt]] : []; },
  };
  const build = () => direct(t, { liveVerify: true, resolver, edgePublicIp: '192.0.2.1', liveVerifyTimeoutMs: 50, tenantMaxPerHour: 1 });
  const h = build();
  const decide = async (name = host) => { const r = await h.ask(name); return [r.status, r.reason]; };
  h.save([h.claim(host, TENANT_A, { txt_value: txt }), h.claim('b.example.test', TENANT_A, { txt_value: txt }),
    h.claim('c.example.test', TENANT_B, { txt_value: txt })]);
  h.save([{ hostname: 'legacy.example.test', status: 'active' }], 'attached_hosts.json');

  assert.deepEqual(await decide(), [200, 'approved_new']);
  const lookups = state.calls;
  assert.ok(lookups > 0);
  assert.deepEqual(await decide(), [200, 'approved_repeat']);
  assert.equal(state.calls, lookups, 'repeats within the window do not look up DNS');

  // A positive result is cached: a host refused by a cap is not looked up again when retried.
  assert.equal((await decide('b.example.test'))[1], 'approval_cap_tenant');
  const afterCap = state.calls;
  assert.equal((await decide('b.example.test'))[1], 'approval_cap_tenant');
  assert.equal(state.calls, afterCap, 'positive cache hit avoids a second lookup');
  h.advance(10 * 60000 + 1);
  assert.equal((await decide('b.example.test'))[1], 'approval_cap_tenant');
  assert.ok(state.calls > afterCap, 'the positive cache expires after 10 minutes');

  // Missing proof => 404 live_verify_failed, cached for a minute, without spending budget.
  state.proof = false;
  assert.deepEqual(await decide('c.example.test'), [404, 'live_verify_failed']);
  const afterFail = state.calls;
  assert.deepEqual(await decide('c.example.test'), [404, 'live_verify_failed']);
  assert.equal(state.calls, afterFail, 'negative cache hit');
  h.advance(61000);
  state.proof = true;
  assert.deepEqual(await decide('c.example.test'), [200, 'approved_new']);

  // Resolver errors fail closed with 503 and are not cached.
  const e = build();
  e.save([e.claim(host, TENANT_A, { txt_value: txt })]);
  state.fail = Object.assign(new Error('boom'), { code: 'ESERVFAIL' });
  assert.deepEqual([(await e.ask(host)).status, (await e.ask(host)).reason], [503, 'live_verify_unavailable']);
  state.fail = null;
  assert.equal((await e.ask(host)).status, 200, 'an outage is not remembered');

  // A hung resolver is cut off at the timeout.
  const slow = direct(t, { liveVerify: true, liveVerifyTimeoutMs: 20, edgePublicIp: '192.0.2.1',
    resolver: { resolveCname: () => new Promise(() => {}), resolve4: () => new Promise(() => {}), resolveTxt: () => new Promise(() => {}) } });
  slow.save([slow.claim(host, TENANT_A, { txt_value: txt })]);
  assert.deepEqual([(await slow.ask(host)).status, (await slow.ask(host)).reason], [503, 'live_verify_unavailable']);

  // The stored claim is never modified by a failed check.
  const stored = readFileSync(`${h.directory}/tenant_hostnames.json`, 'utf8');
  state.proof = false;
  h.advance(61000);
  await h.ask('c.example.test');
  assert.equal(readFileSync(`${h.directory}/tenant_hostnames.json`, 'utf8'), stored);
});

test('TLS ask live verify never looks up unknown names, static hosts or legacy attachments', async (t) => {
  let calls = 0;
  const count = async () => { calls++; throw new Error('must not be called'); };
  const h = direct(t, { liveVerify: true, resolver: { resolveCname: count, resolve4: count, resolveTxt: count },
    staticHosts: ['static.example.test'], checksPerMinute: 100000 });
  h.save([h.claim('pending.example.test', TENANT_A, { status: 'pending' }), h.claim('unverified.example.test', TENANT_A, { verified_at: null }),
    h.claim('reserved.example.test', TENANT_A, { txt_value: 'x' })]);
  h.save([{ hostname: 'legacy.example.test', status: 'active' }], 'attached_hosts.json');
  for (const name of ['unknown.example.test', 'pending.example.test', 'unverified.example.test', 'reserved.example.test',
    '*.example.test', 'bad host', '']) assert.equal((await h.ask(name)).status, 404, name);
  assert.equal(calls, 0);
  assert.equal(h.ask('static.example.test').status, 200);
  assert.equal(h.ask('legacy.example.test').status, 200);
  assert.equal(calls, 0, 'static and legacy hosts have no claim proof to re-check');
});

test('TLS ask live verify is on by default and TLS_ASK_LIVE_VERIFY=0 disables it', async (t) => {
  const previous = process.env.TLS_ASK_LIVE_VERIFY;
  t.after(() => { if (previous === undefined) delete process.env.TLS_ASK_LIVE_VERIFY; else process.env.TLS_ASK_LIVE_VERIFY = previous; });
  const resolver = { async resolveCname() { return []; }, async resolve4() { return []; }, async resolveTxt() { return []; } };
  // Each flag value reads the same store.
  const dir = tempDir(t);
  writeJson('tenant_hostnames.json', [{ hostname: 'app.example.test', tenant_id: TENANT_A, status: 'active', verified_at: new Date(0).toISOString(), txt_value: 'x' }], 0o600, dir);
  const make = (value) => {
    if (value === undefined) delete process.env.TLS_ASK_LIVE_VERIFY; else process.env.TLS_ASK_LIVE_VERIFY = value;
    return createTlsAsk({ dataDir: dir, tlsAskEnabled: true, resolver, attachTarget: 'attach.example.test',
      altAttachTarget: 'edge.example.test', reservedSuffixes: [], edgePublicIp: '192.0.2.1', now: () => 0 });
  };
  assert.equal((await make(undefined)('app.example.test')).reason, 'live_verify_failed');
  assert.equal((await make('1')('app.example.test')).reason, 'live_verify_failed');
  assert.equal(make('0')('app.example.test').reason, 'approved_new');
});

test('TLS ask static hosts spend the global approval cap but never a tenant cap', (t) => {
  const h = direct(t, { staticHosts: ['s1.example.test', 's2.example.test'], tenantMaxPerHour: 1, globalMaxPerHour: 2 });
  h.save([h.claim('a.example.test')]);
  assert.equal(h.ask('s1.example.test').status, 200);
  assert.equal(h.ask('a.example.test').status, 200);
  assert.equal(h.ask('s2.example.test').status, 429);
  assert.equal(h.ask('s1.example.test').status, 200);
});

test('TLS ask revoked hosts are denied even inside their approval window', (t) => {
  const h = direct(t);
  h.save([h.claim('a.example.test')]);
  assert.equal(h.ask('a.example.test').status, 200);
  h.save([]);
  assert.equal(h.ask('a.example.test').status, 404);
});

test('TLS ask unknown, unclaimed and unverified hosts never consume tenant or approval budget', (t) => {
  const h = direct(t, { tenantMaxPerHour: 1, globalMaxPerHour: 1, checksPerMinute: 100000 });
  h.save([h.claim('real.example.test'), h.claim('unverified.example.test', TENANT_A, { verified_at: null }),
    h.claim('pending.example.test', TENANT_A, { status: 'pending' })]);
  for (let i = 0; i < 500; i++) assert.equal(h.ask(`random-${i}.example.test`).status, 404);
  for (let i = 0; i < 50; i++) {
    for (const host of ['unverified.example.test', 'pending.example.test']) assert.equal(h.ask(host).status, 404);
  }
  assert.equal(h.ask('real.example.test').status, 200, 'single tenant and global slot are still free');
  assert.equal(h.ask('real.example.test').status, 200);
  assert.deepEqual(Object.keys(h.ask.counts()).sort(), ['approved_new', 'approved_repeat', 'denied', 'denied_cached']);
});

test('TLS ask caches denies for a TTL and answers them without store reads', (t) => {
  const h = direct(t, { checksPerMinute: 1000 });
  h.save([]);
  assert.equal(h.ask('cold.example.test').status, 404);
  const read = t.mock.method(fs, 'readFileSync');
  const stat = t.mock.method(fs, 'statSync');
  for (let i = 0; i < 100; i++) assert.equal(h.ask('cold.example.test').status, 404);
  assert.equal(read.mock.callCount(), 0);
  assert.equal(stat.mock.callCount(), 0);
  assert.equal(h.ask.counts().denied, 1);
  assert.equal(h.ask.counts().denied_cached, 100);
  h.advance(59000);
  assert.equal(h.ask('cold.example.test').status, 404);
  assert.equal(h.ask.counts().denied_cached, 101);
  h.advance(1000);
  assert.equal(h.ask('cold.example.test').status, 404);
  assert.equal(h.ask.counts().denied, 2, 'expired entries are evaluated again');
});

test('TLS ask a just-verified claim is approved immediately despite a cached deny', async (t) => {
  const h = setup(t);
  const host = 'activation.example.test';
  let proof;
  const claims = createClaims({ dataDir: h.directory, attachTarget: 'attach.example.test',
    altAttachTarget: 'edge.example.test', reservedSuffixes: [],
    resolver: { resolveCname: async () => ['attach.example.test'], resolveTxt: async () => [[proof]] },
  }, () => {});
  proof = claims.create(TENANT_A, { hostname: host, hostname_limit: 5 }).body.dns.txt.value;
  for (let i = 0; i < 5; i++) assert.equal(await h.status(host), 404);
  await claims.verify(TENANT_A, host);
  assert.equal(await h.status(host), 200);
});

test('TLS ask invalidates cached denies when either store changes', (t) => {
  const h = direct(t);
  h.save([]);
  assert.equal(h.ask('a.example.test').status, 404);
  assert.equal(h.ask('b.example.test').status, 404);
  h.save([h.claim('a.example.test', TENANT_A, { verified_at: null })]);
  assert.equal(h.ask('a.example.test').status, 404);
  h.save([h.claim('a.example.test')]);
  assert.equal(h.ask('a.example.test').status, 200);
  h.save([{ hostname: 'b.example.test', status: 'active' }], 'attached_hosts.json');
  assert.equal(h.ask('b.example.test').status, 200);
});

test('TLS ask invalidates cached denies for external store changes within a second', (t) => {
  const h = direct(t);
  h.save([]);
  assert.equal(h.ask('a.example.test').status, 404);
  fs.writeFileSync(`${h.directory}/tenant_hostnames.json`, JSON.stringify([h.claim('a.example.test')]));
  h.advance(1000);
  assert.equal(h.ask('a.example.test').status, 200);
});

test('TLS ask check cap returns 429 for unknown names but never blocks approved hosts', (t) => {
  const h = direct(t, { checksPerMinute: 5 });
  h.save([h.claim('app.example.test')]);
  assert.equal(h.ask('app.example.test').status, 200);
  for (let i = 0; i < 5; i++) assert.equal(h.ask(`u${i}.example.test`).status, 404);
  const limited = h.ask('u-new.example.test');
  assert.equal(limited.status, 429);
  assert.equal(limited.retry_after, 60);
  assert.equal(h.ask('*.example.test').status, 429, 'malformed names share the cap');
  for (let i = 0; i < 50; i++) assert.equal(h.ask('app.example.test').status, 200);
  assert.equal(h.ask('u0.example.test').status, 404, 'cached denies are answered');
  // A newly verified host is still approvable while anonymous checks are capped.
  h.save([h.claim('app.example.test'), h.claim('late.example.test')]);
  assert.equal(h.ask('late.example.test').status, 200);
  h.advance(60000);
  assert.equal(h.ask('u-new.example.test').status, 404);
});

test('TLS ask check cap defaults to 600 per minute and the env var overrides it', (t) => {
  const previous = process.env.TLS_ASK_CHECKS_PER_MINUTE;
  t.after(() => { if (previous === undefined) delete process.env.TLS_ASK_CHECKS_PER_MINUTE; else process.env.TLS_ASK_CHECKS_PER_MINUTE = previous; });
  delete process.env.TLS_ASK_CHECKS_PER_MINUTE;
  let h = direct(t);
  h.save([]);
  let limited = 0;
  for (let i = 0; i < 610; i++) if (h.ask(`d${i}.example.test`).status === 429) limited++;
  assert.equal(limited, 10);
  process.env.TLS_ASK_CHECKS_PER_MINUTE = '3';
  h = direct(t);
  h.save([]);
  assert.deepEqual([0, 1, 2, 3].map((i) => h.ask(`d${i}.example.test`).status), [404, 404, 404, 429]);
});

test('TLS ask memory stays bounded under a flood of random names', (t) => {
  const { ask: probe } = direct(t, { denyCacheMax: 50, checksPerMinute: 1e9 });
  for (let i = 0; i < 5000; i++) probe(`flood-${i}.example.test`);
  // Evicted names are re-evaluated (counted as denied) rather than retained.
  const before = probe.counts().denied;
  probe('flood-0.example.test');
  assert.equal(probe.counts().denied, before + 1);
  const recent = probe.counts().denied_cached ?? 0;
  probe('flood-4999.example.test');
  assert.equal(probe.counts().denied_cached, recent + 1);
  // Invalid inputs are never cached.
  for (let i = 0; i < 100; i++) probe(`bad name ${i}`);
  const invalid = probe.counts().invalid;
  probe('bad name 1');
  assert.equal(probe.counts().invalid, invalid + 1);
});

test('TLS ask approval and deny maps are bounded by their caps', (t) => {
  const h = direct(t, { globalMaxPerHour: 5, tenantMaxPerHour: 1000 });
  const names = Array.from({ length: 200 }, (_, i) => `n${i}.example.test`);
  h.save(names.map((n) => h.claim(n)));
  const statuses = names.map((n) => h.ask(n).status);
  assert.equal(statuses.filter((s) => s === 200).length, 5);
  assert.equal(statuses.filter((s) => s === 429).length, 195);
});

test('TLS ask fails closed on store read errors, including for approved hosts, and recovers', (t) => {
  const h = direct(t);
  h.save([h.claim('app.example.test')]);
  assert.equal(h.ask('app.example.test').status, 200);
  fs.writeFileSync(`${h.directory}/tenant_hostnames.json`, '{not json');
  h.advance(1000);
  assert.equal(h.ask('app.example.test').status, 404);
  assert.equal(h.ask('app.example.test').reason, 'store_error');
  h.save([h.claim('app.example.test')]);
  h.advance(1000);
  assert.equal(h.ask('app.example.test').status, 200);
  // Structurally invalid records also fail closed.
  h.save([null]);
  h.advance(1000);
  assert.equal(h.ask('app.example.test').status, 404);
  assert.equal(h.ask('app.example.test').reason, 'store_error');
});

test('TLS ask logs aggregate reasons only and never denied hostnames', async (t) => {
  const h = setup(t);
  h.save([h.claim('app.example.test')]);
  await h.status('secret-probe.example.test');
  await h.status('secret-probe.example.test');
  await h.status('app.example.test');
  assert.deepEqual(h.logs, [{ status: 404, reason: 'denied' }, { status: 404, reason: 'denied_cached' },
    { status: 200, reason: 'approved_new' }]);
  assert.ok(!JSON.stringify(h.logs).includes('secret-probe'));
});

test('TLS ask 429 responses carry Retry-After and JSON retry_after', async (t) => {
  const h = setup(t, { globalMaxPerHour: 1 });
  h.save([h.claim('a.example.test'), h.claim('b.example.test')]);
  assert.equal(await h.status('a.example.test'), 200);
  const limited = await h.ask('b.example.test');
  assert.equal(limited.statusCode, 429);
  assert.equal(limited.headers['retry-after'], '3600');
  assert.deepEqual(JSON.parse(limited.body), { error: 'rate_limited', retry_after: 3600 });
});

test('Caddy snippet is the go-live form: global ask block plus the catch-all site', () => {
  const snippet = readFileSync(new URL('../deploy/caddy/on-demand-tls.snippet', import.meta.url), 'utf8');
  assert.match(snippet, /^\{\s*on_demand_tls\s*\{\s*ask http:\/\/127\.0\.0\.1:8789\/tls\/ask\s*\}\s*\}/m);
  assert.match(snippet, /^https:\/\/ \{\s*tls \{\s*on_demand\s*\}\s*import fdctl\s*reverse_proxy 127\.0\.0\.1:8787\s*\}/m);
});

test('TLS ask checks external changes once per second and only rereads changed stores', async (t) => {
  const h = setup(t);
  h.save([]);
  assert.equal((await h.ask()).statusCode, 404);
  const read = t.mock.method(fs, 'readFileSync');
  const stat = t.mock.method(fs, 'statSync');
  h.advance(1000);
  assert.equal((await h.ask()).statusCode, 404);
  assert.equal(read.mock.callCount(), 0);
  assert.equal(stat.mock.callCount(), 2);
  fs.writeFileSync(`${h.directory}/tenant_hostnames.json`, JSON.stringify([h.claim('app.example.test')]));
  assert.equal((await h.ask()).statusCode, 404);
  assert.equal(stat.mock.callCount(), 2);
  h.advance(1000);
  assert.equal((await h.ask()).statusCode, 200);
  assert.equal(read.mock.callCount(), 1);
});

test('TLS ask flag off avoids all store reads and metering', async (t) => {
  const h = setup(t, { tlsAskEnabled: false });
  const read = t.mock.method(fs, 'readFileSync');
  const stat = t.mock.method(fs, 'statSync');
  for (let i = 0; i < 310; i++) assert.equal((await h.ask()).statusCode, 404);
  assert.equal(read.mock.callCount(), 0);
  assert.equal(stat.mock.callCount(), 0);
});

test('TLS ask requires one active owner and denies legacy/tenant coexistence', async (t) => {
  const h = setup(t, { checksPerMinute: 1000 });
  const host = 'app.example.test';
  const owner = h.claim(host);
  for (const competitor of [owner, h.claim(host, { tenant_id: TENANT_B }),
    h.claim(host, { tenant_id: 'invalid', verified_at: null })]) {
    h.save([owner, competitor]);
    assert.equal((await h.ask()).statusCode, 404);
  }
  h.save([owner, h.claim(host, { status: 'pending', tenant_id: TENANT_B })]);
  assert.equal((await h.ask()).statusCode, 200);
  for (const status of ['active', 'pending', 'expired']) {
    for (const legacyStatus of ['active', 'pending']) {
      h.save([h.claim(host, { status })]);
      h.save([{ hostname: host, status: legacyStatus }], 'attached_hosts.json');
      assert.equal((await h.ask()).statusCode, 404);
    }
  }
  h.save([]);
  h.save([{ hostname: host, status: 'active' }, { hostname: host, status: 'active' }], 'attached_hosts.json');
  assert.equal((await h.ask()).statusCode, 404);
  h.save([{ hostname: host, status: 'active' }], 'attached_hosts.json');
  assert.equal((await h.ask()).statusCode, 200);
});
