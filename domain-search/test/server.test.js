import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createServer, truncateIp } from '../src/server.js';
import { createService } from '../src/service.js';
import { createRegistrar } from '../src/registrar.js';
import { mockRegistrar, taken, available, price, xml, username, apiKey } from './fixtures.js';

process.env.REGISTRAR_USERNAME = username;
process.env.REGISTRAR_API_KEY = apiKey;

async function start(t, options = {}) {
  const logs = [];
  const server = createServer({ logger: (line) => logs.push(line), ...options });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const request = (path, { method = 'GET', headers = {} } = {}) => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: server.address().port, path, method, headers, agent: false }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        try {
          for (const secret of ['opensrs', 'OPENSRS', username, apiKey]) assert.ok(!raw.includes(secret), `response leaked ${secret}`);
          assert.equal(res.headers['cache-control'], 'no-store');
          assert.equal(res.headers['content-type'], 'application/json');
          assert.equal(res.headers['x-content-type-options'], 'nosniff');
          resolve({ status: res.statusCode, headers: res.headers, body: raw ? JSON.parse(raw) : null });
        } catch (error) { reject(error); }
      });
    });
    req.on('error', reject);
    req.end();
  });
  return { request, logs };
}

test('HTTP routes, methods, validation, normalized response, no leaks or query logs', async (t) => {
  const registrar = createRegistrar({ transport: async ({ body }) => xml(body.includes('LOOKUP')
    ? { ...available, response_text: `opensrs OPENSRS ${username} ${apiKey}`, attributes: { status: 'available', secret: apiKey } }
    : price()) });
  const { request, logs } = await start(t, { service: createService({ registrar, perIpLimit: 30 }), trustProxy: true });
  assert.deepEqual((await request('/api/domains/health')).body, { ok: true });
  assert.equal((await request('/api/domains/search?q=EXAMPLE.COM.', { headers: { 'X-Forwarded-For': '192.0.2.123, 198.51.100.100' } })).body.query, 'example.com');
  for (const value of ['', '-a.com', 'a-.com', 'a..com', 'xn--abc.com', 'ex ample.com', 'example.zz', 'a.b.com', 'a'.repeat(64) + '.com', '<script>', apiKey]) {
    const response = await request(`/api/domains/search?q=${encodeURIComponent(value)}`);
    assert.equal(response.status, 400);
    assert.deepEqual(response.body, { error: 'invalid_domain' });
  }
  assert.equal((await request('/api/domains/search')).status, 400);
  assert.equal((await request(`/unknown/${username}?key=${apiKey}`)).status, 404);
  for (const method of ['POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD']) {
    const response = await request('/api/domains/search?q=example.com', { method });
    assert.equal(response.status, 405);
    assert.equal(response.headers.allow, 'GET');
  }
  assert.ok(logs.some((line) => line.endsWith('192.0.2.0/24')));
  for (const secret of ['192.0.2.123', '198.51.100', 'q=', username, apiKey, '<script>', 'opensrs', 'OPENSRS']) assert.ok(!logs.join('\n').includes(secret));
  assert.ok(logs.every((line) => /^(?:\/api\/domains\/(?:search|health)|unknown) \d{3} \d+ms (?:[\da-f:./]+|unknown)$/.test(line)));
});

test('per-IP rate limit produces 429 and Retry-After; first hop and window reset', async (t) => {
  let time = 0;
  const registrar = mockRegistrar({ lookup: () => taken });
  const service = createService({ registrar, now: () => time, perIpLimit: 2 });
  const { request } = await start(t, { service, trustProxy: true });
  const search = (ip) => request('/api/domains/search?q=example', { headers: { 'X-Forwarded-For': ip } });
  assert.equal((await search('192.0.2.10, 203.0.113.1')).status, 200);
  assert.equal((await search('192.0.2.10, 203.0.113.2')).status, 200);
  const limited = await search('192.0.2.10');
  assert.equal(limited.status, 429);
  assert.deepEqual(limited.body, { error: 'rate_limited' });
  assert.equal(limited.headers['retry-after'], '600');
  assert.equal((await search('192.0.2.11')).status, 200);
  time = 599_001;
  assert.equal((await search('192.0.2.10')).headers['retry-after'], '1');
  time = 600_000;
  assert.equal((await search('192.0.2.10')).status, 200);
  assert.equal(registrar.calls.length, 5);
});

test('proxy headers ignored by default and health does not spend search limit', async (t) => {
  const { request, logs } = await start(t, {
    service: createService({ registrar: mockRegistrar({ lookup: () => taken }), perIpLimit: 1 }), trustProxy: false,
  });
  assert.equal((await request('/api/domains/health')).status, 200);
  assert.equal((await request('/api/domains/search?q=example', { headers: { 'X-Forwarded-For': '192.0.2.1' } })).status, 200);
  assert.equal((await request('/api/domains/search?q=example', { headers: { 'X-Forwarded-For': '192.0.2.2' } })).status, 429);
  assert.ok(logs.every((line) => line.endsWith('127.0.0.0/24')));
});

test('default limit is ten searches; IPv6 canonical forms cannot bypass limit', async (t) => {
  const { request } = await start(t, { service: createService({ registrar: mockRegistrar({ lookup: () => taken }) }), trustProxy: true });
  for (let index = 0; index < 10; index++) {
    assert.equal((await request('/api/domains/search?q=example', { headers: { 'X-Forwarded-For': '2001:db8::1' } })).status, 200);
  }
  assert.equal((await request('/api/domains/search?q=example', { headers: { 'X-Forwarded-For': '2001:0db8:0:0:0:0:0:1' } })).status, 429);
});

test('upstream failures and unexpected service errors return safe bodies', async (t) => {
  const leak = `opensrs OPENSRS ${username} ${apiKey}`;
  const { request } = await start(t, { service: createService({ registrar: mockRegistrar({ lookup: () => { throw new Error(leak); } }) }) });
  const response = await request('/api/domains/search?q=example');
  assert.equal(response.status, 200);
  assert.equal(response.body.degraded, 'upstream_unavailable');
  assert.ok(response.body.results.every((entry) => entry.status === 'unknown'));
  const broken = await start(t, { service: { rateLimit: () => ({ allowed: true }), search: async () => { throw new Error(leak); } } });
  assert.equal((await broken.request('/api/domains/search?q=example')).status, 503);
});

test('IP log masking handles IPv4, compressed/expanded IPv6, mapped IPv4, and invalid text', () => {
  for (const [ip, expected] of [
    ['192.0.2.129', '192.0.2.0/24'], ['::ffff:192.0.2.129', '192.0.2.0/24'],
    ['2001:db8:abcd:1234::1', '2001:db8:abcd::/48'], ['2001:0db8:0000::1', '2001:db8:0::/48'],
    ['::1', '0:0:0::/48'], ['bad\nlog', 'unknown'],
  ]) assert.equal(truncateIp(ip), expected);
});
