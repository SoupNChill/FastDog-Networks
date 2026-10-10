import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { hostnameTable, longestHost, reservedSuffixes } from './helpers/fixtures.js';
import http from 'node:http';
import { listen, jsonRequest, expectError } from './helpers/http.js';
import { fakeResolver } from './helpers/resolver.js';
import { fixedClock } from './helpers/clock.js';

const edgeFile = new URL('../src/onboard/hostname.js', import.meta.url);
const portalFile = new URL('../portal/src/hostname.js', import.meta.url);
const skip = existsSync(edgeFile) ? false : 'lane A not merged: hostname normalizer absent';

test('hostname fixtures exercise the exact length boundaries', () => {
  assert.equal(longestHost.length, 253);
  assert.equal(longestHost.split('.')[0].length, 63);
});

test('in-memory server proves the isolation assertion rejects a leaking implementation', async (t) => {
  let leak = false;
  const server = await listen(t, http.createServer((_req, res) => {
    res.writeHead(leak ? 200 : 404, { 'content-type': 'application/json' });
    res.end(JSON.stringify(leak ? { hostname: 'app.example.com', status: 'active' } : { error: 'hostname_not_found' }));
  }));
  expectError(await jsonRequest(server, '/'), 404, 'hostname_not_found');
  leak = true;
  const leaked = await jsonRequest(server, '/');
  assert.throws(() => expectError(leaked, 404, 'hostname_not_found'), { code: 'ERR_ASSERTION' });
});

test('fake resolver is programmable and clock advances without sleeping', async () => {
  const resolver = fakeResolver();
  resolver.set('CNAME', 'app.example.com', ['attach.example-edge.test']);
  resolver.set('A', 'app.example.com', ['192.0.2.10']);
  resolver.set('TXT', '_fastdog-challenge.app.example.com', [['fake-', 'value']]);
  assert.deepEqual(await resolver.resolveCname('APP.EXAMPLE.COM.'), ['attach.example-edge.test']);
  assert.deepEqual(await resolver.resolve4('app.example.com'), ['192.0.2.10']);
  assert.deepEqual(await resolver.resolveTxt('_fastdog-challenge.app.example.com'), [['fake-', 'value']]);
  await assert.rejects(resolver.resolve4('missing.example.com'), { code: 'ENODATA' });
  assert.equal(resolver.calls.length, 4);
  const clock = fixedClock();
  const initial = clock.now();
  clock.advance(60_001);
  assert.equal(clock.now() - initial, 60_001);
});

test('hostname normalization contract table', { skip }, async (t) => {
  const { normalizeHostname, isReserved } = await import(edgeFile.href);
  for (const row of hostnameTable) {
    await t.test(JSON.stringify(row.input) ?? 'undefined', () => {
      if (row.error) assert.throws(() => normalizeHostname(row.input), { code: row.error });
      else assert.equal(normalizeHostname(row.input), row.expected);
    });
  }
  for (const host of ['reserved.example.com', 'x.reserved.example.com', 'x.y.reserved.example.com']) {
    assert.equal(isReserved(normalizeHostname(host), reservedSuffixes), true);
  }
  for (const host of ['notreserved.example.com', 'reserved.example.com.example.test']) {
    assert.equal(isReserved(normalizeHostname(host), reservedSuffixes), false);
  }
});

test('portal and edge hostname tables cannot drift', {
  skip: skip || (existsSync(portalFile) ? false : 'lane B has no separate hostname copy'),
}, async () => {
  const edge = await import(edgeFile.href);
  const portal = await import(portalFile.href);
  const outcome = (fn, input) => {
    try { return { value: fn(input) }; } catch (error) { return { code: error.code }; }
  };
  for (const row of hostnameTable) {
    const expected = row.error ? { code: row.error } : { value: row.expected };
    assert.deepEqual(outcome(edge.normalizeHostname, row.input), expected);
    assert.deepEqual(outcome(portal.normalizeHostname, row.input), expected);
  }
});
