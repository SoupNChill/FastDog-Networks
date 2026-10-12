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
  const { client } = await f.seed();
  for (const path of ['/../package.json', '/%2e%2e/package.json', '/css/%2e%2e/%2e%2e/package.json', '/css/..%2f..%2fpackage.json', '/%252e%252e/package.json', '//example.com/login', 'http://example.com/login', '/css/site.css%00', '/css%5c..%5cpackage.json', '/accounts.json', '/fonts/../../package.json']) {
    assert.equal((await request(f.port, path)).status, 404, path);
  }
  for (const path of ['/login', '/signup', '/hostname', '/connect', '/domains', '/plan', '/js/login.js', '/css/site.css', '/css/portal.css', '/fonts/Mulish-Regular.ttf', '/favicon.svg', '/logos/hound-dark.svg', '/logos/hound-light.svg']) {
    const response = await client.call(path);
    assert.equal(response.status, 200, path);
    assert.match(response.headers['content-security-policy'], /default-src 'self'/);
    assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
    assert.equal(response.headers['referrer-policy'], 'no-referrer');
  }
  for (const path of ['/favicon.svg', '/logos/hound-dark.svg', '/logos/hound-light.svg']) {
    const response = await request(f.port, path);
    assert.equal(response.headers['content-type'], 'image/svg+xml');
    assert.equal(response.text, readFileSync(new URL(`../../site${path}`, import.meta.url), 'utf8'));
  }
  assert.equal((await request(f.port, '/logos/lockup-dark.svg')).status, 404);
  assert.equal((await f.client.call('/api/me')).headers['cache-control'], 'no-store');
});

test('public files contain no inline scripts, handlers, external assets or stored credentials', () => {
  const publicDir = fileURLToPath(new URL('../public/', import.meta.url));
  for (const file of readdirSync(publicDir).filter((name) => name.endsWith('.html'))) {
    const html = readFileSync(join(publicDir, file), 'utf8');
    assert.match(html, /<link rel="icon" type="image\/svg\+xml" href="\/favicon.svg">/);
    assert.match(html, /<source srcset="\/logos\/hound-dark.svg" media="\(prefers-color-scheme: light\)">/);
    assert.match(html, /<img src="\/logos\/hound-light.svg"[^>]*alt="FastDog Networks">/);
    assert.ok(html.includes('<span>Portal</span>'));
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
  const css = readFileSync(fileURLToPath(new URL('../public/css/portal.css', import.meta.url)), 'utf8');
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

test('portal styles keep submit actions primary and mobile navigation together', () => {
  const css = readFileSync(new URL('../public/css/portal.css', import.meta.url), 'utf8');
  const primary = css.match(/\.portal-body button\[type="submit"\] \{([^}]+)\}/)[1];
  assert.match(primary, /background: var\(--accent\)/);
  assert.match(primary, /color: var\(--bg\)/);
  assert.match(css, /\.site-header button \{[^}]*border: 1px solid var\(--rule\);[^}]*background: var\(--panel\)/);
  assert.match(css, /@media \(max-width: 760px\) \{\s*\.site-header \{ flex-direction: column/);
  assert.match(css, /@media \(max-width: 420px\)[\s\S]*nav \{ gap: 0 8px; flex-wrap: nowrap; width: 100%/);
  assert.match(css, /nav button \{ padding: 0 8px; font: inherit; white-space: nowrap/);
});

test('Connect hides its form for empty or pending-only accounts and shows active hostnames', async () => {
  const html = readFileSync(new URL('../public/connect.html', import.meta.url), 'utf8');
  assert.match(html, /<form method="post" id="connect" hidden>/);
  assert.match(html, /<p id="connect-empty" hidden>[^<]+<a href="\/hostname">/);
  const source = readFileSync(new URL('../public/js/connect.js', import.meta.url), 'utf8').replace(/^import .*;\n/gm, '');
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  for (const hostnames of [[], [{ hostname: 'pending.example.test', status: 'pending' }], [
    { hostname: 'pending.example.test', status: 'pending' },
    { hostname: 'first.example.test', status: 'active' },
    { hostname: 'chosen.example.test', status: 'active' },
  ]]) {
    const options = [];
    const nodes = {
      '#hostname': { append(option) { options.push(option); }, get value() { return (options.find((o) => o.selected) || options[0])?.value || ''; } },
      '#connect': { hidden: true }, '#connect-empty': { hidden: true },
    };
    const watched = [];
    await new AsyncFunction('api', 'init', 'form', 'message', 'watchAgent', 'document', 'location', source)(
      async () => ({ hostnames }), async () => {}, () => {}, (error) => assert.fail(error),
      (hostname) => watched.push(hostname),
      { querySelector: (id) => nodes[id], createElement: () => ({}) },
      { search: '?hostname=chosen.example.test' },
    );
    const active = hostnames.filter((h) => h.status === 'active');
    assert.deepEqual(options.map((o) => o.value), active.map((h) => h.hostname));
    assert.equal(nodes['#connect'].hidden, active.length === 0);
    assert.equal(nodes['#connect-empty'].hidden, active.length > 0);
    assert.deepEqual(watched, active.length ? ['chosen.example.test'] : []);
  }
});
