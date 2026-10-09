import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createService, normalizeDomain } from '../src/service.js';
import { mockRegistrar, available, taken, invalid, price, username, apiKey } from './fixtures.js';

const single = (options = {}) => createService({ registrar: mockRegistrar(), alternates: ['com'], ...options });
const bad = ['', '-a.com', 'a-.com', 'a..com', 'xn--abc.com', 'ab--cd.com', 'ex ample.com', 'example.zz', 'a.b.com', `${'a'.repeat(64)}.com`, '<script>', ' example.com', 'é.com', 'example.com..', null, 'a'.repeat(254)];

test('normalization and validation; invalid input makes no calls', async () => {
  const registrar = mockRegistrar();
  const service = createService({ registrar });
  for (const [input, expected] of [['example', 'example.com'], ['example.com', 'example.com'], ['EXAMPLE.COM.', 'example.com'], ['a-b.dev', 'a-b.dev'], ['a', 'a.com'], [`${'a'.repeat(63)}.io`, `${'a'.repeat(63)}.io`]]) {
    assert.equal(normalizeDomain(input), expected);
  }
  for (const input of bad) {
    assert.equal(normalizeDomain(input), null);
    assert.deepEqual(await service.search(input), { error: 'invalid_domain' });
  }
  assert.equal(registrar.calls.length, 0);
});

test('available prices new and renewal; requested name first and four unique alternates', async () => {
  const registrar = mockRegistrar({ getPrice: (_, type) => price(type === 'new' ? '14.50' : '16') });
  const response = await createService({ registrar }).search('EXAMPLE.IO.');
  assert.equal(response.query, 'example.io');
  assert.equal(response.cached, false);
  assert.deepEqual(response.results.map((r) => r.domain), ['example.io', 'example.com', 'example.net', 'example.org', 'example.dev']);
  assert.equal(registrar.calls.length, 15);
  assert.deepEqual(response.results[0], { domain: 'example.io', status: 'available', premium: false, price_year: '14.50', price_renewal: '16.00', currency: 'USD' });
  assert.deepEqual(registrar.calls.slice(0, 3), [['lookup', 'example.io'], ['getPrice', 'example.io', 'new'], ['getPrice', 'example.io', 'renewal']]);
});

test('taken only does lookup; invalid upstream shape becomes unknown', async () => {
  const registrar = mockRegistrar({ lookup: () => taken });
  const response = await single({ registrar }).search('example');
  assert.equal(response.results[0].status, 'taken');
  assert.equal(response.results[0].price_year, null);
  assert.equal(registrar.calls.length, 1);
  const result = await single({ registrar: mockRegistrar({ lookup: () => invalid }) }).search('example');
  assert.equal(result.results[0].status, 'unknown');
  assert.equal(result.degraded, 'upstream_unavailable');
  assert.ok(!JSON.stringify(result).includes('Invalid domain syntax'));
});

test('premium from lookup reason or either price response', async () => {
  for (const source of ['lookup', 'new', 'renewal']) {
    const registrar = mockRegistrar({
      lookup: () => source === 'lookup' ? { ...available, attributes: { status: 'available', reason: 'Premium Name' } } : available,
      getPrice: (_, type) => price('100.00', type === source ? { is_registry_premium: '1', registry_premium_group: 'secret-tier' } : {}),
    });
    const response = await single({ registrar }).search('example');
    assert.equal(response.results[0].premium, true);
    assert.ok(!JSON.stringify(response).includes('secret-tier'));
  }
});

test('per-domain cache hits, normalized keys, expiry, and defensive copies', async () => {
  let time = 0;
  const registrar = mockRegistrar({ lookup: () => taken });
  const service = createService({ registrar, now: () => time, cacheTTL: 100 });
  const first = await service.search('example');
  first.results[0].status = 'available';
  const second = await service.search('EXAMPLE.COM.');
  assert.equal(second.cached, true);
  assert.equal(second.results[0].status, 'taken');
  assert.equal(registrar.calls.length, 5);
  time = 99;
  await service.search('example');
  assert.equal(registrar.calls.length, 5);
  time = 100;
  assert.equal((await service.search('example')).cached, false);
  assert.equal(registrar.calls.length, 10);
  const overlapping = await service.search('example.net');
  assert.equal(overlapping.cached, true);
  assert.equal(registrar.calls.length, 10);
});

test('default cache lasts three hours', async () => {
  let time = 0;
  const registrar = mockRegistrar({ lookup: () => taken });
  const service = single({ registrar, now: () => time });
  await service.search('example');
  time = 3 * 60 * 60 * 1000 - 1;
  assert.equal((await service.search('example')).cached, true);
  time++;
  assert.equal((await service.search('example')).cached, false);
});

test('daily cap checked before each call, partial prices, cached results, UTC-day reset', async () => {
  let time = Date.parse('2026-10-09T23:59:59Z');
  const registrar = mockRegistrar();
  const service = createService({ registrar, now: () => time, dailyCap: 4 });
  const first = await service.search('example');
  assert.equal(registrar.calls.length, 4);
  assert.equal(first.degraded, 'daily_cap');
  assert.equal(first.results[0].price_renewal, '14.50');
  assert.equal(first.results[1].status, 'available');
  assert.equal(first.results[1].price_year, null);
  assert.ok(first.results.slice(2).every((r) => r.status === 'unknown'));
  const second = await service.search('example');
  assert.equal(second.results[0].price_year, '14.50');
  assert.equal(registrar.calls.length, 4);
  time += 1000;
  const third = await service.search('example');
  assert.equal(third.results[1].price_renewal, '14.50');
  assert.equal(registrar.calls.length, 8);
  const partial = await single({ dailyCap: 2 }).search('example');
  assert.equal(partial.results[0].price_year, '14.50');
  assert.equal(partial.results[0].price_renewal, null);
  assert.equal(partial.degraded, 'daily_cap');
  const zero = await single({ dailyCap: 0 }).search('example');
  assert.equal(zero.results[0].status, 'unknown');
});

test('concurrent searches share work and cannot exceed cap', async () => {
  const registrar = mockRegistrar();
  const service = createService({ registrar, dailyCap: 3 });
  const responses = await Promise.all([service.search('example'), service.search('example'), service.search('other')]);
  assert.equal(registrar.calls.length, 3);
  assert.ok(responses.every((response) => response.degraded === 'daily_cap'));
  const sharedRegistrar = mockRegistrar();
  const shared = single({ registrar: sharedRegistrar });
  await Promise.all([shared.search('example'), shared.search('example')]);
  assert.equal(sharedRegistrar.calls.length, 3);
});

test('failures and timeouts become unknown, no raw fields/secrets; failures consume budget and are not cached', async () => {
  const leak = `opensrs OPENSRS ${username} ${apiKey}`;
  for (const stage of ['lookup', 'getPrice']) {
    const registrar = mockRegistrar({ [stage]: () => { throw new Error(`ETIMEDOUT ${leak}`); } });
    const service = single({ registrar, dailyCap: 3 });
    const response = await service.search('example');
    assert.equal(response.degraded, 'upstream_unavailable');
    assert.equal(response.results[0].status, 'unknown');
    for (const secret of ['opensrs', 'OPENSRS', username, apiKey, 'response_code', 'attributes']) assert.ok(!JSON.stringify(response).includes(secret));
    await service.search('example');
    await service.search('example');
    assert.equal((await service.search('example')).degraded, 'daily_cap');
    assert.equal(registrar.calls.length, 3);
  }
  for (const value of ['NaN', '-1', leak, '14.123', null]) {
    const response = await single({ registrar: mockRegistrar({ getPrice: () => price(value) }) }).search('example');
    assert.equal(response.results[0].status, 'unknown');
    assert.equal(response.degraded, 'upstream_unavailable');
  }
});

test('daily cap counter persists across restarts; bad file or new day resets', async () => {
  const statePath = join(mkdtempSync(join(tmpdir(), 'ds-')), 'daily-count.json');
  let time = Date.UTC(2026, 9, 9, 12);
  const make = () => createService({ registrar: mockRegistrar(), alternates: ['com'], now: () => time, dailyCap: 3, statePath });
  await make().search('a.com'); // 3 upstream calls (lookup + new + renewal price)
  assert.deepEqual(JSON.parse(readFileSync(statePath, 'utf8')), { day: '2026-10-09', calls: 3 });
  assert.equal((await make().search('b.com')).degraded, 'daily_cap'); // restarted service resumes at 3 of 3
  writeFileSync(statePath, '{not json');
  assert.equal((await make().search('c.com')).degraded, undefined); // corrupt file resets
  writeFileSync(statePath, JSON.stringify({ day: '2026-10-08', calls: 3 }));
  assert.equal((await make().search('d.com')).degraded, undefined); // stale day resets
  writeFileSync(statePath, JSON.stringify({ day: '2026-10-09', calls: -5 }));
  assert.equal((await make().search('e.com')).degraded, undefined); // invalid count resets
});
