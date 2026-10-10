import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { createEdgeClient } from '../src/edge-client.js';
import { createDomainClient } from '../src/domain-client.js';
import { statuses } from '../src/errors.js';
import { fixture, listen, request, fakeSecret, tids } from './helpers.js';

test('edge client uses scoped internal paths, key header, bounded timeout and contract errors', async (t) => {
  const portalKey = fakeSecret();
  const calls = [];
  let response = { hostname: 'app.example.com' };
  let status = 200;
  let hang = false;
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    calls.push({ path: req.url, method: req.method, key: req.headers['x-fastdog-portal-key'], body: Buffer.concat(chunks).toString('utf8') });
    if (hang) return;
    res.writeHead(status, { 'content-type': 'application/json', 'retry-after': '9' });
    res.end(typeof response === 'string' ? response : JSON.stringify(response));
  });
  const port = await listen(t, server);
  const edge = createEdgeClient({ baseUrl: `http://127.0.0.1:${port}`, portalKey, timeout: 500 });
  await edge.createHostname(tids[0], 'App.Example.COM.', 3);
  assert.deepEqual(calls[0], { path: `/internal/v1/tenants/${tids[0]}/hostnames`, method: 'POST', key: portalKey, body: JSON.stringify({ hostname: 'app.example.com', hostname_limit: 3 }) });
  for (const method of ['listHostnames', 'getHostname', 'verifyHostname', 'rotateCredential', 'getAgent', 'deleteHostname']) await edge[method](tids[0], 'app.example.com');
  assert.match(calls[4].path, /\/credentials\/rotate$/);
  assert.equal(calls[6].method, 'DELETE');
  for (const [code, expected] of Object.entries(statuses)) {
    status = expected;
    response = { error: code, detail: fakeSecret() };
    await assert.rejects(edge.listHostnames(tids[0]), (error) => error.code === code && error.status === expected
      && error.message === code && (code !== 'rate_limited' || error.retry_after === 9));
  }
  response = { error: 'upstream-private-detail' };
  await assert.rejects(edge.listHostnames(tids[0]), { code: 'internal_error' });
  response = '<html>broken</html>';
  await assert.rejects(edge.listHostnames(tids[0]), { code: 'internal_error' });
  hang = true;
  await assert.rejects(edge.listHostnames(tids[0]), { code: 'internal_error' });
  assert.throws(() => edge.listHostnames('../invalid'), { code: 'invalid_tenant' });
});

test('domain client performs only a read and never forwards portal credentials', async (t) => {
  let received;
  const server = http.createServer((req, res) => {
    received = { url: req.url, method: req.method, headers: req.headers };
    res.end(JSON.stringify({ results: [] }));
  });
  const port = await listen(t, server);
  await createDomainClient({ baseUrl: `http://127.0.0.1:${port}` }).search('example.com', '192.0.2.1');
  assert.equal(received.url, '/api/domains/search?q=example.com');
  assert.equal(received.method, 'GET');
  assert.equal(received.headers['x-fastdog-portal-key'], undefined);
});

test('static paths reject traversal, encoding and absolute-form requests with security headers', async (t) => {
  const f = await fixture(t);
  for (const path of ['/../package.json', '/%2e%2e/package.json', '/css/%2e%2e/%2e%2e/package.json', '/css/..%2f..%2fpackage.json', '/%252e%252e/package.json', '//example.com/login', 'http://example.com/login', '/css/site.css%00', '/css%5c..%5cpackage.json', '/accounts.json', '/fonts/../../package.json']) {
    assert.equal((await request(f.port, path)).status, 404, path);
  }
  for (const path of ['/login', '/signup', '/hostname', '/connect', '/domains', '/plan', '/js/login.js', '/css/site.css', '/css/portal.css', '/fonts/Mulish-Regular.ttf']) {
    const response = await request(f.port, path);
    assert.equal(response.status, 200, path);
    assert.match(response.headers['content-security-policy'], /default-src 'self'/);
    assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    assert.equal(response.headers['referrer-policy'], 'no-referrer');
  }
  assert.equal((await f.client.call('/api/me')).headers['cache-control'], 'no-store');
});

test('public files contain no inline scripts, handlers, external assets or stored credentials', () => {
  const publicDir = fileURLToPath(new URL('../public/', import.meta.url));
  for (const file of readdirSync(publicDir).filter((name) => name.endsWith('.html'))) {
    const html = readFileSync(join(publicDir, file), 'utf8');
    assert.ok(html.includes('href="/css/site.css"'));
    assert.ok(html.includes('href="/css/portal.css"'));
    assert.equal([...html.matchAll(/<script\b/g)].length, 1);
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i);
    assert.doesNotMatch(html, /\son\w+\s*=|style\s*=|(?:https?:)?\/\/|data:/i);
  }
  for (const file of readdirSync(join(publicDir, 'js'))) {
    const source = readFileSync(join(publicDir, 'js', file), 'utf8');
    assert.doesNotMatch(source, /https?:\/\/|localStorage|sessionStorage|innerHTML|eval\(/);
  }
  const css = readFileSync(fileURLToPath(new URL('../../site/css/portal.css', import.meta.url)), 'utf8');
  assert.doesNotMatch(css, /#[a-f\d]{3,8}\b|rgba?\(|animation|transition/i);
  assert.ok(css.includes('min-height: 44px'));
  for (const [, name] of css.matchAll(/var\((--[\w-]+)\)/g)) assert.ok(['--bg', '--panel', '--rule', '--ink', '--sub', '--muted', '--accent', '--healthy'].includes(name));
});

test('domain validation failures map to the contract and private errors are discarded', async (t) => {
  const server = http.createServer((_req, res) => {
    res.writeHead(400);
    res.end(JSON.stringify({ error: 'invalid_domain', detail: fakeSecret() }));
  });
  const port = await listen(t, server);
  const client = createDomainClient({ baseUrl: `http://127.0.0.1:${port}` });
  await assert.rejects(client.search('invalid'), { code: 'invalid_hostname', status: 400 });
});
