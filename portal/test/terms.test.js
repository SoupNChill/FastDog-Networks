import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createInvites } from '../src/invites.js';
import { renderHtml } from '../src/static.js';
import { TERMS_VERSION, PRIVACY_VERSION, siteOrigin, termsUrls } from '../src/terms.js';
import { fixture, fakeSecret, request } from './helpers.js';

const publicDir = new URL('../public/', import.meta.url);

test('terms versions and site URLs default to a safe placeholder origin', () => {
  assert.equal(TERMS_VERSION, '2026-10-17-draft');
  assert.equal(PRIVACY_VERSION, '2026-10-17-draft');
  for (const value of [undefined, '', 'http://site.example.test', 'https://site.example.test/path', 'javascript:alert(1)', 'not a url']) {
    assert.equal(siteOrigin({ SITE_ORIGIN: value }), 'https://example.invalid', String(value));
  }
  assert.equal(siteOrigin({ SITE_ORIGIN: 'https://site.example.test/' }), 'https://site.example.test');
  assert.deepEqual(termsUrls({ SITE_ORIGIN: 'https://site.example.test' }), { terms: 'https://site.example.test/terms/',
    privacy: 'https://site.example.test/privacy/', faq: 'https://site.example.test/faq/' });
});

test('signup page has a required terms checkbox linking both documents in a new tab', async (t) => {
  const html = renderHtml(readFileSync(new URL('signup.html', publicDir)), { SITE_ORIGIN: 'https://site.example.test' }).toString();
  assert.match(html, /<input type="checkbox" id="accept-terms" name="accept_terms" required>/);
  assert.match(html, /I agree to the <a href="https:\/\/site\.example\.test\/terms\/" target="_blank" rel="noopener">Terms of Service<\/a> and <a href="https:\/\/site\.example\.test\/privacy\/" target="_blank" rel="noopener">Privacy Policy<\/a>/);
  const f = await fixture(t);
  const served = await request(f.port, '/signup');
  assert.doesNotMatch(served.text, /\{\{(TERMS|PRIVACY)_URL\}\}/);
  assert.match(served.text, /href="https:\/\/[^"]+\/terms\/" target="_blank" rel="noopener"/);
});

test('signup without accepting the terms is generic and creates nothing', async (t) => {
  const f = await fixture(t);
  const email = 'new@example.test';
  const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email });
  for (const accept_terms of [undefined, false, 'on', 'true', 1]) {
    const result = await f.client.call('/api/signup', 'POST', { email, password: fakeSecret(), invite_code: code, accept_terms });
    assert.equal(result.status, 200);
    assert.deepEqual(result.data, { ok: true });
    f.advance(3600001); // Stay under the per-IP signup limit.
    await f.client.call('/api/me');
  }
  const saved = f.store.read('accounts');
  assert.equal(saved.users.length, 0);
  assert.equal(saved.tenants.length, 0);
  assert.equal(saved.invites[0].redeemed_at ?? null, null);
  assert.deepEqual(f.messages, []);
});

test('accepted signup stores versions, timestamp and a salted IP hash, never the raw IP', async (t) => {
  const f = await fixture(t);
  const invites = createInvites({ dataDir: f.dataDir, now: f.now });
  for (const email of ['first@example.test', 'second@example.test']) {
    const code = invites.mint({ email });
    assert.deepEqual((await f.client.call('/api/signup', 'POST', { email, password: fakeSecret(), invite_code: code, accept_terms: true })).data, { ok: true });
  }
  const [first, second] = f.store.read('accounts').users;
  assert.deepEqual(Object.keys(first.terms).sort(), ['accepted_at', 'ip_hash', 'privacy_version', 'tos_version']);
  assert.equal(first.terms.tos_version, TERMS_VERSION);
  assert.equal(first.terms.privacy_version, PRIVACY_VERSION);
  assert.equal(first.terms.accepted_at, new Date(f.now()).toISOString());
  assert.match(first.terms.ip_hash, /^[a-f0-9]{64}$/);
  assert.equal(second.terms.ip_hash, first.terms.ip_hash, 'salt is stable per install');
  const accounts = readFileSync(join(f.dataDir, 'accounts.json'), 'utf8');
  assert.ok(!accounts.includes('127.0.0.1') && !accounts.includes('::1'));
  const saltFile = join(f.dataDir, 'install-salt.json');
  assert.equal(statSync(saltFile).mode & 0o777, 0o600);
  assert.match(JSON.parse(readFileSync(saltFile, 'utf8')).salt, /^[a-f0-9]{64}$/);
  assert.equal(f.messages.length, 2);
});

test('IP hashes differ between installs', async (t) => {
  const hashes = [];
  for (let i = 0; i < 2; i++) {
    const f = await fixture(t);
    const code = createInvites({ dataDir: f.dataDir, now: f.now }).mint({ email: 'new@example.test' });
    await f.client.call('/api/signup', 'POST', { email: 'new@example.test', password: fakeSecret(), invite_code: code, accept_terms: true });
    hashes.push(f.store.read('accounts').users[0].terms.ip_hash);
  }
  assert.notEqual(hashes[0], hashes[1]);
});
