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
const HOUR_MS = 3600000;

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
    txt_value: 'synthetic-proof', status: 'active', verified_at: new Date(time).toISOString(), ...extra });
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
  const claim = (hostname, tenant = TENANT_A, extra = {}) => ({ hostname, tenant_id: tenant, txt_value: 'synthetic-proof', status: 'active',
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

test('TLS ask accepts canonical verified active claims and observes revocation immediately', async (t) => {
  const h = setup(t);
  h.save([h.claim('app.example.test'), h.claim('xn--bcher-kva.example.test')]);
  for (const domain of ['app.example.test', 'xn--bcher-kva.example.test']) {
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
  for (const name of ['forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-real-ip', 'via', 'cf-connecting-ip']) {
    for (const value of ['', '127.0.0.1']) assert.equal((await h.ask(undefined, { headers: { [name]: value } })).statusCode, 404);
  }
  for (const address of ['127.0.0.1', '::1', '::ffff:127.0.0.1']) assert.equal((await h.ask(undefined, { address })).statusCode, 200);
});

test('TLS ask approval set: static allow-list is normalized and the only way to approve reserved names', (t) => {
  const h = direct(t, { staticHosts: [' STATIC.Example.Test. ', 'reserved.example.test', 'bad host', ''] });
  h.save([h.claim('sub.reserved.example.test')]);
  assert.equal(h.ask('static.example.test').status, 200);
  assert.equal(h.ask('STATIC.EXAMPLE.TEST').status, 404);
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
  assert.equal(h.ask('y.example.test').status, 200, 'domain buckets are tenant isolated');
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

  // Resolver errors fail closed with 503 and are remembered for only 10 seconds.
  const e = build();
  e.save([e.claim(host, TENANT_A, { txt_value: txt })]);
  state.fail = Object.assign(new Error('boom'), { code: 'ESERVFAIL' });
  assert.deepEqual([(await e.ask(host)).status, (await e.ask(host)).reason], [503, 'live_verify_unavailable']);
  const afterOutage = state.calls;
  state.fail = null;
  assert.equal((await e.ask(host)).status, 503, 'a recent outage is cached briefly');
  assert.equal(state.calls, afterOutage, 'no lookup while the outage is cached');
  e.advance(10001);
  assert.equal((await e.ask(host)).status, 200, 'an outage is forgotten after 10 seconds');

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

test('TLS ask static hosts spend the global cap and repeats remain free', (t) => {
  const h = direct(t, { staticHosts: ['s1.example.test', 's2.example.test'], tenantMaxPerHour: 1, globalMaxPerHour: 2 });
  h.save([h.claim('a.example.test')]);
  assert.equal(h.ask('s1.example.test').status, 200);
  assert.equal(h.ask('a.example.test').status, 200);
  assert.equal(h.ask('s2.example.test').reason, 'approval_cap_global');
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
  const h = direct(t, { globalMaxPerHour: 5, globalReserve: 0, tenantMaxPerHour: 1000 });
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
  assert.match(snippet, /^https:\/\/ \{\s*tls \{\s*on_demand\s*\}\s*@sni_mismatch not host \{http\.request\.tls\.server_name\}\s*respond @sni_mismatch 421\s*import fdctl\s*reverse_proxy 127\.0\.0\.1:8787\s*\}/m);
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
  assert.equal(stat.mock.callCount(), 3);
  fs.writeFileSync(`${h.directory}/tenant_hostnames.json`, JSON.stringify([h.claim('app.example.test')]));
  assert.equal((await h.ask()).statusCode, 404);
  assert.equal(stat.mock.callCount(), 3);
  h.advance(1000);
  assert.equal((await h.ask()).statusCode, 200);
  assert.equal(read.mock.callCount(), 2, 'changed claims plus locked approval-state read');
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
      assert.equal((await h.ask()).statusCode, status !== 'active' && legacyStatus === 'active' ? 200 : 404);
    }
  }
  h.save([]);
  h.save([{ hostname: host, status: 'active' }, { hostname: host, status: 'active' }], 'attached_hosts.json');
  assert.equal((await h.ask()).statusCode, 404);
  h.save([{ hostname: host, status: 'active' }], 'attached_hosts.json');
  assert.equal((await h.ask()).statusCode, 200);
});

test('TLS ask caps approvals per registered domain over 7 days (default 40, env override)', (t) => {
  const h = direct(t, { domainMaxPerHour: 1000, tenantMaxPerHour: 1000, globalMaxPerHour: 1000 });
  const hosts = Array.from({ length: 41 }, (_, i) => `h${i}.week.example.test`);
  h.save([...hosts.map((host) => h.claim(host)), h.claim('other.example.org')]);
  for (const host of hosts.slice(0, 40)) {
    assert.equal(h.ask(host).status, 200, host);
    h.advance(2 * HOUR_MS); // Spread out so only the weekly window can refuse.
  }
  // 80 hours have passed, so the first approvals are still inside the 7-day window.
  const refused = h.ask(hosts[40]);
  assert.deepEqual([refused.status, refused.reason], [429, 'approval_cap_domain_week']);
  assert.ok(refused.retry_after > 0);
  // Other registered domains are unaffected, and the window rolls after 7 days.
  assert.equal(h.ask('other.example.org').status, 200);
  h.advance(7 * 24 * HOUR_MS);
  assert.equal(h.ask(hosts[40]).status, 200);

  const tight = direct(t, { domainMaxPerHour: 1000, domainMaxPerWeek: 2 });
  tight.save(['a', 'b', 'c'].map((n) => tight.claim(`${n}.tight.example.test`)));
  assert.deepEqual(['a', 'b', 'c'].map((n) => tight.ask(`${n}.tight.example.test`).status), [200, 200, 429]);

  const previous = process.env.TLS_ASK_DOMAIN_WEEK_MAX;
  t.after(() => { if (previous === undefined) delete process.env.TLS_ASK_DOMAIN_WEEK_MAX; else process.env.TLS_ASK_DOMAIN_WEEK_MAX = previous; });
  process.env.TLS_ASK_DOMAIN_WEEK_MAX = '1';
  const envCap = direct(t, { domainMaxPerHour: 1000 });
  envCap.save(['a', 'b'].map((n) => envCap.claim(`${n}.env.example.test`)));
  assert.deepEqual(['a', 'b'].map((n) => envCap.ask(`${n}.env.example.test`).status), [200, 429]);
});

const restart = (directory, time, extra = {}) => createTlsAsk({ dataDir: directory, tlsAskEnabled: true, liveVerify: false,
  now: () => time, attachTarget: 'attach.example.test', altAttachTarget: 'edge.example.test',
  reservedSuffixes: ['reserved.example.test'], ...extra });

test('TLS ask approval budgets persist across restarts, atomically, pruned to 7 days', (t) => {
  const first = direct(t, { tenantMaxPerHour: 1 });
  first.save(['a', 'b'].map((n) => first.claim(`${n}.persist.example.test`)));
  assert.equal(first.ask('a.persist.example.test').status, 200);
  const file = `${first.directory}/tls_ask_approvals.json`;
  const stored = JSON.parse(readFileSync(file, 'utf8'));
  assert.deepEqual(stored.map(({ host, tenant, domain }) => [host, tenant, domain]), [['a.persist.example.test', TENANT_A, 'example.test']]);
  assert.ok(Number.isFinite(stored[0].at));
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(fs.readdirSync(first.directory).filter((name) => name.endsWith('.tmp')), []);

  // A restart (new instance, same directory and clock) still sees the spent budgets.
  const time = Date.UTC(2026, 0, 1);
  const again = restart(first.directory, time, { tenantMaxPerHour: 1 });
  assert.equal(again('a.persist.example.test').reason, 'approved_repeat');
  assert.equal(again('b.persist.example.test').reason, 'approval_cap_tenant');
  const weekly = restart(first.directory, time + 2 * HOUR_MS, { domainMaxPerWeek: 1 });
  assert.equal(weekly('b.persist.example.test').reason, 'approval_cap_domain_week');

  // Entries older than 7 days are pruned on load; a missing file starts empty.
  fs.writeFileSync(file, JSON.stringify([{ host: 'old.persist.example.test', tenant: TENANT_A, domain: 'example.test', at: time - 8 * 24 * HOUR_MS }]));
  const pruned = restart(first.directory, time, { domainMaxPerWeek: 1 });
  assert.equal(pruned('b.persist.example.test').reason, 'approved_new');
  assert.ok(!JSON.parse(readFileSync(file, 'utf8')).some((entry) => entry.host.startsWith('old.')));
  const empty = direct(t);
  empty.save([empty.claim('z.persist.example.test')]);
  assert.equal(empty.ask('z.persist.example.test').reason, 'approved_new');
});

test('TLS ask treats a corrupt state file as full windows for 10 minutes without crashing', (t) => {
  const seed = direct(t);
  seed.save([seed.claim('a.corrupt.example.test')]);
  for (const raw of ['{not json', '{"a":1}', JSON.stringify([{ host: 1 }])]) {
    fs.writeFileSync(`${seed.directory}/tls_ask_approvals.json`, raw);
    const errors = [];
    const original = console.error;
    console.error = (...args) => errors.push(args.join(' '));
    let time = Date.UTC(2026, 0, 1);
    let ask;
    try { ask = restart(seed.directory, undefined, { now: () => time }); } finally { console.error = original; }
    assert.equal(errors.length, 1, raw);
    assert.match(errors[0], /starting empty history automatically/);
    assert.equal(readFileSync(`${seed.directory}/tls_ask_approvals.json.corrupt-${time}`, 'utf8'), raw);
    assert.doesNotMatch(errors[0], /corrupt\.example/);
    const blocked = ask('a.corrupt.example.test');
    assert.deepEqual([blocked.status, blocked.reason], [429, 'approval_state_unavailable']);
    assert.ok(blocked.retry_after > 0 && blocked.retry_after <= 600);
    time += 9 * 60000;
    assert.equal(ask('a.corrupt.example.test').status, 429, 'still paused');
    time += 61000;
    assert.equal(ask('a.corrupt.example.test').status, 200, 'resumes after 10 minutes');
    assert.ok(Array.isArray(JSON.parse(readFileSync(`${seed.directory}/tls_ask_approvals.json`, 'utf8'))), 'unreadable file is replaced');
  }
});


test('TLS ask rejects noncanonical names and hides method handling from untrusted requests', async (t) => {
  const h = setup(t);
  h.save([h.claim('app.example.test'), h.claim('xn--bcher-kva.example.test')]);
  for (const name of ['APP.EXAMPLE.TEST', 'app.example.test.', ' app.example.test', 'bücher.example.test']) {
    assert.equal(await h.status(name), 404);
  }
  assert.equal(await h.status(undefined, { method: 'POST', address: '192.0.2.1' }), 404);
  for (const name of ['forwarded', 'x-forwarded-for', 'x-real-ip', 'via', 'cf-connecting-ip']) {
    assert.equal(await h.status(undefined, { method: 'POST', headers: { [name]: '' } }), 404);
  }
  assert.equal(await h.status(undefined, { method: 'POST' }), 405);
});

test('TLS ask weekly buckets isolate tenants and legacy/static hosts', (t) => {
  const h = direct(t, { domainMaxPerWeek: 1 });
  h.save([h.claim('a.example.test'), h.claim('b.example.test'), h.claim('c.example.test', TENANT_B)]);
  h.save([{ hostname: 'legacy.example.test', status: 'active' }], 'attached_hosts.json');
  assert.equal(h.ask('a.example.test').status, 200);
  h.advance(HOUR_MS);
  assert.equal(h.ask('b.example.test').reason, 'approval_cap_domain_week');
  assert.equal(h.ask('c.example.test').status, 200);
  assert.equal(h.ask('legacy.example.test').status, 200);
});

test('TLS ask common suffix additions retain the registered label', () => {
  for (const suffix of ['me.uk', 'ltd.uk', 'ne.jp', 'or.jp', 'go.jp', 'id.au', 'gob.mx']) {
    assert.equal(registeredDomain(`x.example.${suffix}`), `example.${suffix}`);
  }
});

test('TLS ask daily host cap survives restart, allows repeats and resets at 24h', (t) => {
  const h = direct(t);
  const host = 'app.example.test';
  h.save([h.claim(host)]);
  for (let i = 0; i < 3; i++) {
    assert.equal(h.ask(host).reason, 'approved_new');
    assert.equal(h.ask(host).reason, 'approved_repeat');
    h.advance(HOUR_MS);
  }
  const start = Date.UTC(2026, 0, 1);
  assert.equal(h.ask(host).reason, 'approval_cap_host_day');
  assert.equal(restart(h.directory, start + 3 * HOUR_MS)(host).retry_after, 21 * 3600);
  assert.equal(restart(h.directory, start + 24 * HOUR_MS)(host).status, 200);
  const previous = process.env.TLS_ASK_HOST_DAY_MAX;
  t.after(() => { if (previous === undefined) delete process.env.TLS_ASK_HOST_DAY_MAX; else process.env.TLS_ASK_HOST_DAY_MAX = previous; });
  process.env.TLS_ASK_HOST_DAY_MAX = '1';
  const capped = direct(t);
  capped.save([capped.claim(host)]);
  assert.equal(capped.ask(host).status, 200);
  capped.advance(HOUR_MS);
  assert.equal(capped.ask(host).reason, 'approval_cap_host_day');
});

test('TLS ask static hosts use reserve and retain week guard', (t) => {
  const h = direct(t, { staticHosts: ['s.example.test', 't.example.test'], globalMaxPerHour: 3,
    tenantMaxPerHour: 1, domainMaxPerHour: 10, domainMaxPerWeek: 1 });
  h.save([h.claim('a.example.test'), h.claim('b.other.test')]);
  assert.equal(h.ask('s.example.test').status, 200);
  assert.equal(h.ask('a.example.test').status, 200);
  assert.equal(h.ask('s.example.test').status, 200);
  assert.equal(h.ask('t.example.test').reason, 'approval_cap_domain_week');
  assert.equal(h.ask('b.other.test').reason, 'approval_cap_global');
});

test('TLS ask global default reserves 20 of 60 approvals for newcomers and static hosts', (t) => {
  const h = direct(t, { tenantMaxPerHour: 100, domainMaxPerHour: 100, domainMaxPerWeek: 100 });
  const hosts = Array.from({ length: 61 }, (_, i) => `h${i}.example.test`);
  h.save(hosts.map(host => h.claim(host)));
  assert.deepEqual(hosts.map(host => h.ask(host).status), [...Array(40).fill(200), ...Array(21).fill(429)]);
});

test('TLS ask refuses approvals if corrupt state cannot be quarantined', (t) => {
  const h = direct(t);
  h.save([h.claim('app.example.test')]);
  fs.writeFileSync(`${h.directory}/tls_ask_approvals.json`, '{invalid');
  const rename = fs.renameSync;
  const log = console.error;
  const messages = [];
  let ask;
  try {
    fs.renameSync = () => { throw new Error('synthetic quarantine failure'); };
    console.error = message => messages.push(message);
    ask = restart(h.directory, Date.UTC(2026, 0, 1));
  } finally {
    fs.renameSync = rename;
    console.error = log;
  }
  assert.match(messages[0], /could not quarantine/);
  assert.deepEqual(ask('app.example.test'), { status: 429, reason: 'approval_state_unavailable', retry_after: 600 });
});

test('global reserve admits new tenants and statics only, warns without names every five minutes', (t) => {
  const messages = [];
  const warn = console.warn;
  console.warn = line => messages.push(line);
  t.after(() => { console.warn = warn; });
  const h = direct(t, { globalMaxPerHour: 4, globalReserve: 2, staticHosts: ['s.example.test'] });
  h.save([h.claim('a.example.test'), h.claim('b.example.test'), h.claim('c.example.test'),
    h.claim('d.example.test', TENANT_B), h.claim('e.example.test', TENANT_B)]);
  assert.equal(h.ask('a.example.test').status, 200);
  assert.equal(h.ask('b.example.test').status, 200);
  assert.equal(h.ask('c.example.test').reason, 'approval_cap_global');
  assert.equal(h.ask('d.example.test').status, 200);
  assert.equal(h.ask('e.example.test').reason, 'approval_cap_global');
  assert.equal(h.ask('s.example.test').status, 200);
  assert.deepEqual(messages, ['tls ask: approval_cap_global']);
  h.advance(5 * 60000);
  assert.equal(h.ask('c.example.test').status, 429);
  assert.equal(messages.length, 2);
  h.advance(HOUR_MS);
  assert.equal(h.ask('c.example.test').status, 200);
});

test('weekly per-host threshold warns once without refusing approvals', (t) => {
  const warnings = [];
  t.mock.method(console, 'warn', message => warnings.push(message));
  const h = direct(t);
  h.save([h.claim('a.example.test')]);
  for (let i = 0; i < 5; i++) {
    assert.equal(h.ask('a.example.test').status, 200);
    assert.equal(h.ask('a.example.test').reason, 'approved_repeat');
    h.advance(24 * HOUR_MS);
  }
  assert.equal(h.ask('a.example.test').status, 200);
  assert.deepEqual(warnings, ['tls ask: approval_cap_host_week (soft)']);
  assert.equal(restart(h.directory, Date.UTC(2026, 0, 6))('a.example.test').status, 200);
  h.advance(2 * 24 * HOUR_MS);
  assert.equal(h.ask('a.example.test').status, 200);
  const previous = process.env.TLS_ASK_HOST_WEEK_MAX;
  t.after(() => { if (previous === undefined) delete process.env.TLS_ASK_HOST_WEEK_MAX; else process.env.TLS_ASK_HOST_WEEK_MAX = previous; });
  process.env.TLS_ASK_HOST_WEEK_MAX = '1';
  const capped = direct(t);
  capped.save([capped.claim('a.example.test')]);
  assert.equal(capped.ask('a.example.test').status, 200);
  capped.advance(24 * HOUR_MS);
  assert.equal(capped.ask('a.example.test').status, 200);
});

test('claims with missing, empty or non-string TXT proofs are excluded even without live verification', (t) => {
  for (const txt_value of [undefined, null, '', ' ', 123, []]) {
    const h = direct(t);
    h.save([h.claim('a.example.test', TENANT_A, { txt_value })]);
    assert.equal(h.ask('a.example.test').status, 404);
  }
});

test('global reserve environment override protects the total and excludes legacy hosts', (t) => {
  const previous = process.env.TLS_ASK_GLOBAL_RESERVE;
  t.after(() => { if (previous === undefined) delete process.env.TLS_ASK_GLOBAL_RESERVE; else process.env.TLS_ASK_GLOBAL_RESERVE = previous; });
  process.env.TLS_ASK_GLOBAL_RESERVE = '1';
  const h = direct(t, { globalMaxPerHour: 2, staticHosts: ['s.example.test', 't.example.test'] });
  h.save([h.claim('a.example.test')]);
  h.save([{ hostname: 'legacy.example.test', status: 'active' }], 'attached_hosts.json');
  assert.equal(h.ask('a.example.test').status, 200);
  assert.equal(h.ask('legacy.example.test').reason, 'approval_cap_global');
  assert.equal(h.ask('s.example.test').status, 200);
  assert.equal(h.ask('t.example.test').reason, 'approval_cap_global');
});

test('operator TLS reset is atomic, host-scoped and reloaded within ten seconds', async (t) => {
  const { spawnSync } = await import('node:child_process');
  const h = direct(t, { hostDayMax: 1 });
  const host = 'reset.example.test';
  const other = 'other.example.test';
  h.save([h.claim(host), h.claim(other)]);
  assert.equal(h.ask(host).status, 200);
  assert.equal(h.ask(other).status, 200);
  h.advance(HOUR_MS);
  assert.equal(h.ask(host).reason, 'approval_cap_host_day');
  const file = `${h.directory}/tls_ask_approvals.json`;
  const reset = () => spawnSync(process.execPath, ['scripts/onboard.js', 'tls-reset', host], {
    encoding: 'utf8', env: { ...process.env, DATA_DIR: h.directory },
  });
  fs.writeFileSync(`${file}.lock`, '');
  assert.notEqual(reset().status, 0);
  assert.equal(JSON.parse(readFileSync(file)).length, 2);
  fs.unlinkSync(`${file}.lock`);
  const result = reset();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(readFileSync(file)).map(e => e.host), [other]);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  const stat = t.mock.method(fs, 'statSync');
  assert.equal(h.ask(host).reason, 'approval_cap_host_day');
  assert.equal(stat.mock.callCount(), 0, 'no extra mtime polling within ten seconds');
  h.advance(10000);
  assert.equal(h.ask(host).reason, 'approved_new');
  assert.equal(h.ask(other).reason, 'approval_cap_host_day');
});

test('TLS reset is not undone by an edge save before the periodic reload', async (t) => {
  const { resetTlsApprovals } = await import('../src/internal/tls-approval-state.js');
  const h = direct(t);
  h.save([h.claim('a.example.test'), h.claim('b.example.test')]);
  assert.equal(h.ask('a.example.test').status, 200);
  resetTlsApprovals('a.example.test', h.directory);
  assert.equal(h.ask('b.example.test').status, 200);
  assert.deepEqual(JSON.parse(readFileSync(`${h.directory}/tls_ask_approvals.json`)).map(e => e.host), ['b.example.test']);
  h.advance(10000);
  assert.equal(h.ask('a.example.test').reason, 'approved_new', 'reload clears stale hourly repeats');
});

test('failed approval writes fail closed, throttle hostname-free logs and recover', (t) => {
  const h = direct(t);
  h.save(['a', 'b', 'c'].map(label => h.claim(`${label}.example.test`)));
  assert.equal(h.ask('a.example.test').reason, 'approved_new');
  const rename = fs.renameSync;
  const failure = t.mock.method(fs, 'renameSync', () => { throw new Error('synthetic'); });
  const errors = t.mock.method(console, 'error', () => {});
  for (let i = 0; i < 3; i++) {
    assert.equal(h.ask('b.example.test').reason, 'approval_state_unavailable');
    assert.equal(h.ask('c.example.test').status, 429);
    assert.equal(h.ask('a.example.test').reason, 'approved_repeat');
  }
  assert.equal(errors.mock.callCount(), 1);
  h.advance(5 * 60000);
  assert.equal(h.ask('b.example.test').status, 429);
  assert.equal(errors.mock.callCount(), 2);
  assert.doesNotMatch(JSON.stringify(errors.mock.calls), /example\.test/);
  failure.mock.mockImplementation(rename);
  assert.equal(h.ask('b.example.test').reason, 'approved_new');
  assert.equal(h.ask('b.example.test').reason, 'approved_repeat');
  assert.deepEqual(JSON.parse(readFileSync(`${h.directory}/tls_ask_approvals.json`)).map(e => e.host), ['a.example.test', 'b.example.test']);
});

test('reserve daily usage survives restart and expires at 24 hours', (t) => {
  const options = { globalMaxPerHour: 10, globalReserve: 10 };
  const h = direct(t, options);
  h.save([h.claim('a.example.test'), h.claim('b.example.test')]);
  assert.equal(h.ask('a.example.test').status, 200);
  const start = Date.UTC(2026, 0, 1);
  assert.equal(restart(h.directory, start + HOUR_MS, options)('b.example.test').reason, 'approval_cap_global');
  assert.equal(restart(h.directory, start + 24 * HOUR_MS, options)('b.example.test').status, 200);
});

test('new and unknown tenants share five hourly reserve slots; established tenants still qualify', (t) => {
  const options = { globalMaxPerHour: 20, globalReserve: 20 };
  const h = direct(t, options);
  const ids = 'abcdefgh'.split('').map(letter => 't_' + letter.repeat(20));
  h.save(ids.map((id, i) => h.claim('h' + i + '.example.test', id)));
  h.save(ids.slice(0, 4).map(id => ({ id, created_at: '2025-12-31T23:00:00Z' }))
    .concat({ id: ids[6], created_at: '2025-12-31T00:00:00Z' },
      { id: ids[7], created_at: 'invalid' }), 'tenants.json');
  for (let i = 0; i < 5; i++) assert.equal(h.ask('h' + i + '.example.test').status, 200);
  const ask = restart(h.directory, Date.UTC(2026, 0, 1), options);
  assert.equal(ask('h5.example.test').status, 429);
  assert.equal(ask('h6.example.test').status, 200);
  assert.equal(ask('h7.example.test').status, 429);
  h.advance(HOUR_MS);
  assert.equal(h.ask('h5.example.test').status, 200);
});

test('approval locks recover dead PIDs and old mtimes, preserve live locks, and unlink after close failure', async (t) => {
  const { updateApprovals } = await import('../src/internal/tls-approval-state.js');
  const directory = tempDir(t);
  const lock = directory + '/tls_ask_approvals.json.lock';
  fs.writeFileSync(lock, String(process.pid));
  assert.throws(() => updateApprovals(directory, list => list), { code: 'EEXIST' });
  fs.utimesSync(lock, new Date(0), new Date(0));
  updateApprovals(directory, list => list);
  assert.equal(fs.existsSync(lock), false);
  fs.writeFileSync(lock, '123456');
  const kill = t.mock.method(process, 'kill', () => { throw Object.assign(new Error(), { code: 'ESRCH' }); });
  updateApprovals(directory, list => list);
  kill.mock.restore();
  const close = fs.closeSync;
  t.mock.method(fs, 'closeSync', fd => { close(fd); throw new Error('synthetic close failure'); });
  assert.throws(() => updateApprovals(directory, list => {
    assert.equal(fs.readFileSync(lock, 'utf8'), String(process.pid));
    return list;
  }));
  assert.equal(fs.existsSync(lock), false);
});

test('test-tenant changes clear cached test-label denies', (t) => {
  const h = direct(t);
  const host = 'e2e-cache.example.test';
  h.save([h.claim(host)]);
  assert.equal(h.ask(host).reason, 'denied');
  assert.equal(h.ask(host).reason, 'denied_cached');
  h.save([TENANT_B], 'test_tenants.json');
  assert.equal(h.ask(host).reason, 'denied');
  h.save([TENANT_A], 'test_tenants.json');
  assert.equal(h.ask(host).status, 200);
});
