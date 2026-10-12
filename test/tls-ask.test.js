import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { readFileSync } from 'node:fs';
import { createInternalServer } from '../src/internal/server.js';
import { writeJson } from '../src/onboard/json.js';
import { tempDir } from './helpers/temp-dir.js';

function setup(t, overrides = {}) {
  let time = Date.UTC(2026, 0, 1);
  const directory = tempDir(t);
  const logs = [];
  const server = createInternalServer({
    portalKey: 'synthetic-portal-key-'.repeat(3), agentToken: 'synthetic-agent-key',
    dataDir: directory, tlsAskEnabled: true, now: () => time,
    attachTarget: 'attach.example.test', altAttachTarget: 'edge.example.test',
    reservedSuffixes: ['reserved.example.test'], logger: (event) => logs.push(event), ...overrides,
  });
  const save = (records, file = 'tenant_hostnames.json') => writeJson(file, records, 0o600, directory);
  const claim = (hostname, extra = {}) => ({ hostname, tenant_id: 't_aaaaaaaaaaaaaaaaaaaa',
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
    assert.equal(res.writableEnded, true);
    return res;
  }
  return { ask, save, claim, logs, advance: () => { time += 60000; } };
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
  assert.deepEqual(h.logs, [{ status: 200 }, { status: 200 }, { status: 404 }]);
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
    { hostname: 'tenant.example.test', status: 'active', tenant_id: 't_aaaaaaaaaaaaaaaaaaaa' }], 'attached_hosts.json');
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

test('TLS ask limits each client across host queries and IPv4 mapped forms, then resets', async (t) => {
  const h = setup(t);
  h.save([h.claim('app.example.test')]);
  for (let i = 0; i < 30; i++) assert.equal((await h.ask()).statusCode, 200);
  const limited = await h.ask(undefined, { address: '::ffff:127.0.0.1' });
  assert.equal(limited.statusCode, 429);
  assert.equal(limited.headers['retry-after'], '60');
  assert.deepEqual(JSON.parse(limited.body), { error: 'rate_limited', retry_after: 60 });
  assert.equal((await h.ask(undefined, { address: '127.0.0.2' })).statusCode, 200);
  h.advance();
  assert.equal((await h.ask()).statusCode, 200);
});

test('TLS ask limits all clients to 300 approvals per minute', async (t) => {
  const h = setup(t);
  h.save([h.claim('app.example.test')]);
  for (let i = 0; i < 300; i++) assert.equal((await h.ask(undefined, { address: `127.0.0.${Math.floor(i / 30) + 1}` })).statusCode, 200);
  assert.equal((await h.ask(undefined, { address: '::1' })).statusCode, 429);
  h.advance();
  assert.equal((await h.ask(undefined, { address: '::1' })).statusCode, 200);
});

test('Caddy snippet places ask inside global on_demand_tls and leaves site commented', () => {
  const snippet = readFileSync(new URL('../deploy/caddy/on-demand-tls.snippet', import.meta.url), 'utf8');
  assert.match(snippet, /^\{\s*on_demand_tls\s*\{\s*ask http:\/\/127\.0\.0\.1:8789\/tls\/ask\s*\}\s*\}/m);
  assert.match(snippet, /# https:\/\/ \{/);
  assert.match(snippet, /#\s+on_demand/);
});

test('TLS ask denied queries cannot consume approval budgets', async (t) => {
  const h = setup(t);
  h.save([h.claim('app.example.test'), h.claim('pending.example.test', { status: 'pending' })]);
  for (let i = 0; i < 310; i++) {
    for (const host of [`unknown-${i}.example.test`, 'pending.example.test', '*.example.test', 'reserved.example.test']) {
      assert.equal((await h.ask(host)).statusCode, 404);
    }
  }
  for (let i = 0; i < 30; i++) assert.equal((await h.ask()).statusCode, 200);
  assert.equal((await h.ask()).statusCode, 429);
  assert.equal((await h.ask('unknown.example.test')).statusCode, 404);
});

test('TLS ask requires one active owner and denies legacy/tenant coexistence', async (t) => {
  const h = setup(t);
  const host = 'app.example.test';
  const owner = h.claim(host);
  for (const competitor of [owner, h.claim(host, { tenant_id: 't_bbbbbbbbbbbbbbbbbbbb' }),
    h.claim(host, { tenant_id: 'invalid', verified_at: null })]) {
    h.save([owner, competitor]);
    assert.equal((await h.ask()).statusCode, 404);
  }
  h.save([owner, h.claim(host, { status: 'pending', tenant_id: 't_bbbbbbbbbbbbbbbbbbbb' })]);
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
