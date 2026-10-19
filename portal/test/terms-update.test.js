import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { TERMS_VERSION, PRIVACY_VERSION, needsTermsUpdate, termsUpdate, termsRecord, acceptTerms } from '../src/terms.js';
import { fixture, temporary, request } from './helpers.js';
import { createStore } from '../src/store.js';

test('terms checks handle missing, malformed, old and current records and fail open', (t) => {
  const store = createStore(temporary(t));
  const current = termsRecord(store, '192.0.2.1', Date.now());
  for (const terms of [undefined, null, [], 'bad', {}, { ...current, tos_version: 'old' },
    { ...current, privacy_version: 'old' }, { ...current, accepted_at: 'bad' }, { ...current, ip_hash: '' }]) {
    assert.equal(needsTermsUpdate({ terms }), true);
  }
  assert.equal(needsTermsUpdate({ terms: current }), false);
  const logs = [];
  assert.deepEqual(termsUpdate({ get terms() { throw Error('private'); } }, {}, (e) => logs.push(e)), {});
  assert.deepEqual(logs, [{ event: 'terms_check_failed', reason: 'check_failed' }]);
  store.write('accounts', { users: [{ id: 'u', terms: current, terms_history: Array(12).fill(current) }] });
  assert.deepEqual(acceptTerms(store, 'u', '192.0.2.2', Date.now()), { ok: true });
  const user = store.read('accounts').users[0];
  assert.equal(user.terms_history.length, 10);
  assert.deepEqual(user.terms_history.at(-1), current);
  assert.match(user.terms.ip_hash, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(user).includes('192.0.2.2'));
  assert.deepEqual(acceptTerms({ read() { throw Error('private'); } }, 'u'), { ok: false });
});

test('terms acceptance is authenticated, CSRF protected, advisory and survives a failed write', async (t) => {
  const logs = [];
  const f = await fixture(t, { logger: (e) => logs.push(e) });
  assert.equal((await f.client.call('/api/me')).data.terms_update, undefined);
  assert.equal((await f.client.call('/api/terms/accept', 'POST', { accept_terms: true })).status, 401);
  const { client, password } = await f.seed();
  const me = await client.call('/api/me');
  assert.equal(me.data.terms_update.required, true);
  assert.match(me.data.terms_update.terms_url, /\/terms\/$/);
  const current = termsRecord(f.store, '192.0.2.1', f.now());
  for (const terms of [{}, { ...current, tos_version: 'old' }, { ...current, privacy_version: 'old' }, current]) {
    const data = f.store.read('accounts');
    data.users[0].terms = terms;
    f.store.write('accounts', data);
    assert.equal(Boolean((await client.call('/api/me')).data.terms_update?.required), terms !== current);
  }
  const outdated = f.store.read('accounts');
  outdated.users[0].terms = { ...current, tos_version: 'old' };
  f.store.write('accounts', outdated);
  assert.equal((await client.call('/api/terms/accept', 'POST', { accept_terms: true }, { 'x-fd-csrf': 'wrong' })).status, 401);
  assert.deepEqual((await client.call('/api/terms/accept', 'POST', {})).data, { error: 'invalid_json' });
  assert.equal((await client.call('/api/hostnames')).status, 200);
  const created = await client.call('/api/hostnames', 'POST', { hostname: 'app.example.test' });
  assert.ok(![401, 403, 404, 405, 500].includes(created.status), `hostname create with outdated terms: ${created.status}`);
  const key = await client.call('/api/keys', 'POST', { password, scopes: ['status:read'] });
  assert.equal(key.status, 201);
  // The key authenticates with outdated terms: an unknown hostname is a 404, not a refusal.
  assert.equal((await request(f.port, '/api/v1/hostnames/missing.example.test/status', { headers: { authorization: `Bearer ${key.data.key}` } })).status, 404);
  // Block salt persistence while leaving account reads and other API state available.
  rmSync(join(f.dataDir, 'install-salt.json'));
  mkdirSync(join(f.dataDir, 'install-salt.json'));
  const failed = await client.call('/api/terms/accept', 'POST', { accept_terms: true });
  assert.deepEqual([failed.status, failed.data], [200, { ok: false }]);
  assert.equal((await client.call('/api/me')).status, 200);
  assert.equal((await client.call('/api/hostnames')).status, 200);
  assert.ok(logs.some((e) => e.event === 'terms_accept_failed'));
  rmSync(join(f.dataDir, 'install-salt.json'), { recursive: true });
  assert.deepEqual((await client.call('/api/terms/accept', 'POST', { accept_terms: true })).data, { ok: true });
  assert.equal((await client.call('/api/me')).data.terms_update, undefined);
  const record = f.store.read('accounts').users[0].terms;
  assert.equal(record.tos_version, TERMS_VERSION);
  assert.equal(record.privacy_version, PRIVACY_VERSION);
  assert.deepEqual(f.store.read('accounts').users[0].terms_history, [outdated.users[0].terms]);
  assert.equal(record.accepted_at, new Date(f.now()).toISOString());
  assert.match(record.ip_hash, /^[a-f0-9]{64}$/);
});

test('shared account initialization and login wire the external advisory panel', () => {
  const read = (name) => readFileSync(new URL('../public/js/' + name, import.meta.url), 'utf8');
  assert.match(read('login.js'), /showTermsUpdate/);
  const source = read('terms-update.js');
  assert.match(source, /checkbox.required = true/);
  assert.match(source, /\/api\/terms\/accept/);
  assert.match(source, /finally \{ finish\(\); \}/);
  assert.match(source, /Continue for now/);
});

test('accept write failure preserves previous account state and logs no private error', (t) => {
  const store = createStore(temporary(t));
  const terms = termsRecord(store, '192.0.2.1', Date.now());
  const original = { users: [{ id: 'u', terms }] };
  store.write('accounts', original);
  const logs = [];
  const broken = { read: store.read, write() { throw Error('private detail'); } };
  assert.deepEqual(acceptTerms(broken, 'u', '192.0.2.2', Date.now(), (e) => logs.push(e)), { ok: false });
  assert.deepEqual(store.read('accounts'), original);
  assert.deepEqual(logs, [{ event: 'terms_accept_failed', reason: 'write_failed' }]);
});

test('prompt continues after successful, refused and failed acceptance', async () => {
  const { showTermsUpdate } = await import('../public/js/terms-update.js');
  const previous = globalThis.document;
  try {
    for (const outcome of ['ok', 'refused', 'network']) {
      const nodes = [];
      globalThis.document = {
        querySelector(selector) { return selector === '#terms-update' ? null : { prepend() {} }; },
        createElement(tag) {
          const node = { tag, children: [], append(...children) { this.children.push(...children); },
            addEventListener(_, fn) { this.submit = fn; }, remove() { this.removed = true; } };
          nodes.push(node);
          return node;
        },
      };
      let continued = 0, calls = 0;
      assert.equal(showTermsUpdate(undefined, () => {}), false);
      assert.equal(showTermsUpdate({ required: true, terms_url: '/terms/', privacy_url: '/privacy/' }, async (path, method, body) => {
        calls++;
        assert.equal(path, '/api/terms/accept');
        assert.equal(method, 'POST');
        assert.deepEqual(body, { accept_terms: true });
        if (outcome === 'network') throw Error('offline');
        return { ok: outcome === 'ok' };
      }, () => continued++), true);
      const panel = nodes[0];
      await panel.submit({ preventDefault() {} });
      assert.equal(calls, 0);
      nodes.find((n) => n.tag === 'input').checked = true;
      await panel.submit({ preventDefault() {} });
      assert.equal(calls, 1);
      assert.equal(continued, 1);
      assert.equal(panel.removed, true);
    }
  } finally { globalThis.document = previous; }
});

test('prompt is skipped when the page has no .portal-body', async () => {
  const { showTermsUpdate } = await import('../public/js/terms-update.js');
  const previousDocument = globalThis.document;
  try {
    globalThis.document = { querySelector: () => null,
      createElement: (tag) => ({ tag, append() {}, addEventListener() {}, remove() {} }) };
    assert.equal(showTermsUpdate({ required: true, terms_url: '/terms/', privacy_url: '/privacy/' }, async () => ({})), false);
  } finally { globalThis.document = previousDocument; }
});

test('the prompt is shown at sign-in only, never from shared page init', () => {
  const read = (name) => readFileSync(new URL('../public/js/' + name, import.meta.url), 'utf8');
  assert.doesNotMatch(read('api.js'), /showTermsUpdate|terms-update/);
  assert.match(read('login.js'), /showTermsUpdate\(me\.terms_update, api, \(\) => location\.assign\(destination\)\)/);
});
