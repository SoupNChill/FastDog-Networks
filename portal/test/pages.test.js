import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, request, fakeSecret } from './helpers.js';
import { pages } from '../src/static.js';

const publicPages = ['/login', '/signup', '/verify-email'];
test('all app pages require an active session, including aliases and trailing slashes', async (t) => {
  const f = await fixture(t);
  for (const path of Object.keys(pages).filter((path) => !publicPages.includes(path))) {
    for (const suffix of ['', '/']) {
      const url = path === '/' ? '/' : path + suffix;
      for (const headers of [{}, { cookie: f.client.cookie }]) {
        const result = await request(f.port, url, { headers });
        assert.equal(result.status, 302, url);
        assert.equal(result.headers.location, '/login');
        assert.equal(result.headers['x-robots-tag'], 'noindex');
      }
    }
  }
  const { client } = await f.seed();
  await client.call('/api/logout', 'POST');
  assert.equal((await client.call('/dashboard')).status, 302);
});

test('all business API routes reject anonymous sessions before calling upstreams', async (t) => {
  const f = await fixture(t);
  for (const [path, methods] of [
    ['/api/hostnames', ['GET', 'POST']], ['/api/hostnames/app.example.test', ['GET', 'DELETE']],
    ['/api/hostnames/app.example.test/verify', ['POST']], ['/api/hostnames/app.example.test/rotate', ['POST']],
    ['/api/hostnames/app.example.test/agent', ['GET']], ['/api/domains/search?q=example.test', ['GET']],
    ['/api/domain-requests', ['GET', 'POST']], ['/api/plan', ['GET']],
  ]) for (const method of methods) {
    assert.equal((await f.client.call(path, method, method === 'GET' ? undefined : {})).status, 401, path);
    assert.equal((await request(f.port, path, { method })).status, 401, path);
  }
  assert.deepEqual(f.calls, []);
  assert.deepEqual(f.searches, []);
});

test('missing and invalid invitations cannot create accounts or send mail', async (t) => {
  const f = await fixture(t);
  for (const invite_code of [undefined, fakeSecret()]) {
    const result = await f.client.call('/api/signup', 'POST', { email: 'invited@example.test', password: fakeSecret(), invite_code });
    assert.deepEqual(result.data, { ok: true }); // Contract deliberately hides invitation validity.
  }
  assert.equal(f.store.read('accounts', { users: [] }).users.length, 0);
  assert.deepEqual(f.messages, []);
});

test('every page renders branded HTML without JS and every referenced asset is served under CSP', async (t) => {
  const f = await fixture(t);
  const { client } = await f.seed();
  const assets = new Set();
  for (const path of Object.keys(pages)) {
    const result = await (publicPages.includes(path) ? request(f.port, path) : client.call(path));
    assert.equal(result.status, 200, path);
    assert.match(result.headers['content-type'], /^text\/html; charset=utf-8$/);
    assert.equal(result.headers['x-robots-tag'], 'noindex');
    for (const pattern of [/<main\b/, /<h1>[^<]+<\/h1>/, /<meta name="robots" content="noindex">/, /<footer\b/, /<noscript>/]) assert.match(result.text, pattern, path);
    assert.doesNotMatch(result.text, /<style\b|style=|<script(?![^>]*src=)/);
    for (const directive of ['script-src', 'style-src', 'font-src', 'default-src']) assert.ok(result.headers['content-security-policy'].includes(`${directive} 'self'`));
    for (const [, asset] of result.text.matchAll(/(?:src|srcset|href)="(\/(?:js|css|logos)\/[^" ]+|\/favicon.svg)"/g)) assets.add(asset);
  }
  for (const asset of assets) {
    const result = await request(f.port, asset);
    assert.equal(result.status, 200, asset);
    assert.ok(result.text.length > 0);
    const type = asset.endsWith('.js') ? 'text/javascript' : asset.endsWith('.css') ? 'text/css' : 'image/svg+xml';
    assert.ok(result.headers['content-type'].startsWith(type), asset);
    assert.equal(result.headers['x-robots-tag'], 'noindex');
    if (asset.endsWith('.css')) for (const [, font] of result.text.matchAll(/url\('(\/fonts\/[^']+)'\)/g)) {
      const response = await request(f.port, font);
      assert.equal(response.status, 200, font);
      assert.equal(response.headers['content-type'], 'font/ttf');
    }
  }
  assert.deepEqual((await request(f.port, '/health')).data, { ok: true });
  const missing = await request(f.port, '/missing');
  assert.equal(missing.status, 404);
  assert.equal(missing.headers['x-robots-tag'], 'noindex');
});

test('verification page clears its fragment and confirms only on submission', async () => {
  const { readFileSync } = await import('node:fs');
  const source = readFileSync(new URL('../public/js/verify-email.js', import.meta.url), 'utf8').replace(/^import .*;\n/gm, '');
  for (const token of [null, fakeSecret()]) {
    let submit;
    let cleared;
    let status;
    const calls = [];
    const node = { hidden: false };
    new Function('api', 'init', 'form', 'message', 'location', 'history', 'document', source)(
      async (...args) => calls.push(args), async () => calls.push('init'),
      (id, callback) => { assert.equal(id, '#verify-email'); submit = callback; },
      (text) => { status = text; }, { hash: token ? `#token=${token}` : '', pathname: '/verify-email' },
      { replaceState: (...args) => { cleared = args; } }, { querySelector: () => node },
    );
    assert.deepEqual(cleared, [null, '', '/verify-email']);
    assert.deepEqual(calls, []);
    await submit();
    if (token) {
      assert.deepEqual(calls, ['init', ['/api/verify-email', 'POST', { token }]]);
      assert.equal(node.hidden, true);
      assert.match(status, /Email verified/);
    } else {
      assert.deepEqual(calls, []);
      assert.match(status, /complete verification link/);
    }
  }
});
