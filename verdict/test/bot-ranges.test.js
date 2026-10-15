import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { compileRanges, createBotRanges, parseCIDR, seed } from '../src/engine/bot-ranges.js';
import { claimedGoodBot, createGoodBotVerifier } from '../src/engine/goodbots.js';
import { asnDb } from '../src/asn/lookup.js';
import { localDecision } from '../src/engine/heuristic.js';
import { scoreAccessLogLine } from '../src/shadow/score.js';
import { refreshBotRanges, sources } from '../scripts/bot-ranges-refresh.js';

const samples = JSON.parse(await readFile(new URL('./fixtures/goodbot-fp-samples.json', import.meta.url)));
const noDNS = { reverse: () => { assert.fail('Unexpected DNS'); } };
const allowedHosts = new Set(['example.test']);
const row = state => ({ host: 'example.test', client_ip: state.ip, request: { headers: { 'User-Agent': [state.ua] } } });
for (const [i, sample] of [...samples, { ...samples[1], ip: '66.249.72.1' }].entries()) {
  test(`published Googlebot sample ${i} allows live and shadow without DNS`, async t => {
    asnDb.loadText('66.249.72.0\t66.249.72.255\t15169\n192.178.6.0\t192.178.6.255\t15169');
    t.after(() => asnDb.clear());
    const verifyBot = createGoodBotVerifier({ resolver: noDNS, ranges: compileRanges(seed) });
    for (const decision of [await localDecision({ ...sample, headers: {}, hosting_asn: true }, { verifyBot, dnsEnabled: false }),
      await scoreAccessLogLine(row(sample), { allowedHosts, hosting: new Set([15169]), verifyBot, dnsEnabled: false })]) {
      assert.equal(decision.action, 'allow');
      assert.equal(decision.reason, 'verified_good_bot');
      assert.deepEqual(decision.reasons, ['verified_good_bot']);
    }
  });
}
test('special crawler claims and Bing use only their own lists', async () => {
  const ranges = compileRanges({ ...seed, bots: { google: seed.bots.google, bing: ['2001:db8:1::/48'] } });
  const verify = createGoodBotVerifier({ ranges, resolver: noDNS });
  for (const ua of ['Googlebot', 'google-extended', 'GoogleOther', 'Storebot-Google', 'Google-InspectionTool', 'GoogleProducer']) {
    assert.equal(claimedGoodBot({ ua }), 'google');
    assert.equal(await verify({ ua, ip: '192.178.6.1' }), 'verified');
    assert.equal(claimedGoodBot({ ua: `x${ua}x` }), null);
  }
  assert.equal(await verify({ ua: 'bingbot', ip: '2001:db8:1::abcd' }), 'verified');
  assert.equal(await verify({ ua: 'bingbot', ip: '192.178.6.1' }, { dnsEnabled: false }), 'pending');
});
test('non-bot never consults ranges or DNS', async () => {
  const verify = createGoodBotVerifier({ resolver: noDNS, ranges: () => assert.fail('Unexpected list lookup') });
  assert.equal(await verify({ ip: '192.178.6.1', ua: 'Mozilla/5.0' }), null);
});
for (const outcome of ['verified', 'failed', 'timeout']) {
  test(`outside ranges uses DNS ${outcome} in live and shadow and caches results`, async () => {
    let calls = 0;
    const state = { ip: '198.51.100.1', ua: 'Googlebot' };
    const verifyBot = createGoodBotVerifier({ timeoutMs: 5, ranges: compileRanges(seed), resolver: {
      reverse: async () => { calls++; return outcome === 'timeout' ? new Promise(() => {}) : ['crawl.googlebot.com']; },
      lookup: async () => [{ address: outcome === 'verified' ? state.ip : '198.51.100.2' }],
    } });
    const expected = outcome === 'verified' ? ['verified_good_bot'] : [outcome === 'failed' ? 'spoofed_good_bot' : 'good_bot_dns_timeout'];
    assert.deepEqual((await localDecision(state, { verifyBot })).reasons, expected);
    const shadow = await scoreAccessLogLine(row(state), { allowedHosts, verifyBot, dnsEnabled: true });
    assert.ok(shadow.reasons.includes(expected[0]));
    assert.equal(calls, 1);
    const pending = await scoreAccessLogLine(row(state), { allowedHosts, verifyBot, dnsEnabled: false });
    assert.ok(pending.reasons.includes('good_bot_pending'));
    assert.ok(!pending.reasons.includes('spoofed_good_bot'));
  });
}
test('CIDR binary search handles overlaps, IPv6 low bits and boundaries', () => {
  const match = compileRanges({ ...seed, bots: { google: ['198.51.100.0/24', '198.51.100.0/28', '2001:db8::10/127'], bing: [] } });
  for (const ip of ['198.51.100.0', '198.51.100.255', '2001:db8::10', '2001:db8::11']) assert.equal(match('google', ip), true);
  for (const ip of ['198.51.101.0', '2001:db8::12', '2001:db8::f', 'invalid']) assert.equal(match('google', ip), false);
  assert.throws(() => compileRanges({ ...seed, bots: { google: ['::/129'], bing: [] } }));
});
test('missing/empty file falls back to DNS; reload throttled and malformed updates retained', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'bot-ranges-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'ranges.json'); let now = 0;
  const ranges = createBotRanges({ file, now: () => now });
  const verify = createGoodBotVerifier({ ranges, resolver: { reverse: async () => ['crawl.googlebot.com'], lookup: async () => [{ address: '198.51.100.1' }] } });
  assert.equal(await verify({ ua: 'Googlebot', ip: '198.51.100.1' }), 'verified');
  await writeFile(file, JSON.stringify({ ...seed, bots: { google: [], bing: [] } })); now += 1000;
  assert.equal(ranges('google', '192.178.6.1'), false);
  assert.equal(await verify({ ua: 'Googlebot', ip: '198.51.100.1' }), 'verified');
  await writeFile(file, JSON.stringify(seed));
  assert.equal(ranges('google', '192.178.6.1'), false);
  now += 1000; assert.equal(ranges('google', '192.178.6.1'), true);
  await writeFile(file, '{'); now += 1000; assert.equal(ranges('google', '192.178.6.1'), true);
});
test('refresh validates each source and atomically preserves prior file on failure', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'bot-refresh-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'ranges.json'); await writeFile(file, JSON.stringify(seed));
  const prior = await readFile(file, 'utf8');
  for (const payload of [{ prefixes: [] }, { prefixes: [{ ipv4Prefix: 'invalid' }] }, { prefixes: Array(100).fill({ ipv4Prefix: '198.51.100.0/24' }) }]) {
    await assert.rejects(refreshBotRanges({ file, fetchImpl: async () => ({ ok: true, json: async () => payload }) }));
    assert.equal(await readFile(file, 'utf8'), prior);
  }
  await assert.rejects(refreshBotRanges({ file, fetchImpl: async () => ({ ok: false }) }));
  assert.equal(await readFile(file, 'utf8'), prior);
  const result = await refreshBotRanges({ file, fetchImpl: async url => ({ ok: true, json: async () => ({ prefixes: Array.from({ length: sources.find(s => s.url === url).min }, (_, i) => ({ ipv4Prefix: `198.51.${i}.0/24` })) }) }) });
  assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), result);
  assert.equal(result.sources.length, 3);
});

test('rejects over-broad CIDRs', () => {
  assert.throws(() => parseCIDR('0.0.0.0/0'), /invalid_prefix/);
  assert.throws(() => parseCIDR('10.0.0.0/8'), /invalid_prefix/);
  assert.throws(() => parseCIDR('::/0'), /invalid_prefix/);
  assert.doesNotThrow(() => parseCIDR('192.178.6.0/24'));
});

test('edge-auth uses seed ranges with DNS off and omits datacenter/spoof signals', async t => {
  const { createApp } = await import('../src/server.js');
  const dir = await mkdtemp(join(tmpdir(), 'bot-edge-')); t.after(() => rm(dir, { recursive: true, force: true }));
  const app = await createApp({ keyFile: join(dir, 'keys.json'), usageFile: join(dir, 'usage.json'), edgeGoodBotDNS: false });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await app.locals.flush(); });
  for (const sample of samples) {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/v1/edge-auth`, { headers: {
      'x-forwarded-host': 'example.test', 'x-forwarded-for': sample.ip, 'user-agent': sample.ua, accept: 'application/json',
    } });
    assert.equal(response.status, 200);
    assert.deepEqual((await response.json()).reasons, ['verified_good_bot']);
  }
});
