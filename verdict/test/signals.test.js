import test from 'node:test';
import assert from 'node:assert/strict';
import { localHeuristic, localDecision, resetVelocity } from '../src/engine/heuristic.js';
import { createGoodBotVerifier } from '../src/engine/goodbots.js';
const chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
const mobile = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36';
const safari = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
const firefox = 'Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0';
const headers = ua => ({ 'user-agent': ua, accept: 'text/html,application/xhtml+xml', 'accept-language': 'en-US,en;q=0.9' });
for (const [name, ua, hints] of [['chrome', chrome, { 'sec-ch-ua': '"Chromium";v="130", "Not_A Brand";v="99"', 'sec-ch-ua-mobile': '?0' }], ['android', mobile, { 'sec-ch-ua': '"Google Chrome";v="130"', 'sec-ch-ua-mobile': '?1' }], ['iphone', safari, {}], ['firefox', firefox, {}]]) {
  for (const path of ['/login', '/api/health', '/products']) test(`false positive: ${name} GET ${path}`, () => {
    const result = localHeuristic({ ua, method: 'GET', path, headers: { ...headers(ua), ...hints } });
    assert.equal(result.action, 'allow'); assert.deepEqual(result.reasons, []);
  });
}
for (const path of ['/wp-login.php', '/xmlrpc.php', '/.env', '/.env.local', '/.git/config', '/phpmyadmin/index.php', '/WP-ADMIN/', '/pma', '/%2eenv']) test(`probe path ${path}`, () => {
  const result = localHeuristic({ path }); assert.equal(result.action, 'block'); assert.ok(result.reasons.includes('probe_path'));
});
for (const path of ['/docs/wp-login.php-help', '/environment', '/.github', '/search?q=/.env']) test(`benign path ${path}`, () => assert.equal(localHeuristic({ path }).action, 'allow'));
const cases = [
  ['missing_accept_language', { headers: {} }],
  ['unusual_header_order', { headers: { ...headers(chrome), _order: ['accept-language', 'accept', 'user-agent'] } }],
  ['header_order_inconsistent', { headers: { ...headers(chrome), header_order: ['user-agent', 'user-agent', 'missing'] } }],
  ['ua_client_hint_mismatch', { ua: firefox, headers: { ...headers(firefox), 'sec-ch-ua': '"Chromium";v="130"' } }],
  ['ua_client_hint_mismatch', { ua: chrome, headers: { 'sec-ch-ua': '"Microsoft Edge";v="130"' } }],
  ['ua_mobile_hint_mismatch', { ua: chrome, headers: { 'sec-ch-ua-mobile': '?1' } }],
  ['ua_mobile_hint_mismatch', { ua: mobile, headers: { 'sec-ch-ua-mobile': '?0' } }],
  ['ua_header_mismatch', { ua: chrome, headers: headers(firefox) }],
  ['malicious_tool', { signals: ['nikto'] }], ['headless_automation', { ua: 'HeadlessChrome/130' }],
  ['sensitive_action', { path: '/login', method: 'POST' }], ['prior_risk', { prior_score: 0.5 }], ['new_account', { account_age_hours: 0.1 }],
];
for (const [id, state] of cases) test(`fired signal ${id}: ${JSON.stringify(state)}`, () => {
  const result = localHeuristic(state); assert.ok(result.reasons.includes(id)); assert.ok(result.score > 0.2);
});
test('header casing, supplied order aliases, absent context and unknown brands', () => {
  for (const key of ['_order', 'header_order']) assert.deepEqual(localHeuristic({ headers: { 'User-Agent': chrome, Accept: '*/*', 'Accept-Language': 'en', [key]: ['User-Agent', 'Accept', 'Accept-Language'] } }).reasons, []);
  assert.deepEqual(localHeuristic({ headers: headers(chrome), header_order: Object.keys(headers(chrome)) }).reasons, []);
  assert.deepEqual(localHeuristic({ ua: safari, headers: { ...headers(safari), 'sec-ch-ua': '"Not A Brand";v="99"' } }).reasons, []);
  assert.deepEqual(localHeuristic({}).reasons, []);
});
test('ASN velocity aggregates IPs, normalizes AS prefix, isolates ASNs and expires', () => {
  resetVelocity();
  for (let i = 0; i < 300; i++) assert.ok(!localHeuristic({ asn: 123, ip: `ip-${i}` }, { now: 0 }).reasons.includes('asn_velocity'));
  assert.ok(localHeuristic({ asn: 'AS123' }, { now: 1 }).reasons.includes('asn_velocity'));
  for (const state of [{ asn: 456 }, {}, { asn: 'invalid' }]) assert.ok(!localHeuristic(state, { now: 1 }).reasons.includes('asn_velocity'));
  assert.ok(!localHeuristic({ asn: 123 }, { now: 60000 }).reasons.includes('asn_velocity'));
  resetVelocity();
});
test('IP velocity signal is independent and expires', () => {
  resetVelocity();
  for (let i = 0; i < 30; i++) localHeuristic({ ip: '192.0.2.1' }, { now: 0 });
  assert.ok(localHeuristic({ ip: '192.0.2.1' }, { now: 1 }).reasons.includes('ip_velocity'));
  assert.ok(!localHeuristic({ ip: '192.0.2.2' }, { now: 1 }).reasons.includes('ip_velocity'));
  assert.ok(!localHeuristic({ ip: '192.0.2.1' }, { now: 60000 }).reasons.includes('ip_velocity'));
});
test('threshold boundaries and complete decision contract', () => {
  for (const [state, action, score] of [[{}, 'allow', 0.2], [{ prior_score: 0.999 }, 'allow', 0.44975], [{ prior_score: 1 }, 'challenge', 0.45], [{ ua: 'sqlmap' }, 'block', 0.75]]) {
    const result = localHeuristic(state); assert.equal(result.action, action); assert.equal(result.score, score);
    for (const key of ['confidence', 'reason', 'reasons', 'engine', 'request_id']) assert.ok(key in result);
    assert.equal(result.engine, 'local_heuristic_v3');
  }
});
const botState = { ua: 'Googlebot/2.1', ip: '192.0.2.1' };
for (const [ua, host] of [['Googlebot/2.1', 'crawl.googlebot.com.'], ['bingbot/2.0', 'crawl.search.msn.com']]) test(`verified ${ua} allows`, async () => {
  const verifyBot = createGoodBotVerifier({ resolver: { reverse: async () => [host], lookup: async () => [{ address: botState.ip }] } });
  const result = await localDecision({ ...botState, ua, path: '/.env' }, { verifyBot });
  assert.equal(result.action, 'allow'); assert.equal(result.reason, 'verified_good_bot'); assert.deepEqual(result.reasons, ['verified_good_bot']);
});
for (const [name, resolver] of [
  ['suffix spoof', { reverse: async () => ['googlebot.com.evil.test'], lookup: async () => { throw Error('must not lookup'); } }],
  ['forward mismatch', { reverse: async () => ['crawl.googlebot.com'], lookup: async () => [{ address: '192.0.2.2' }] }],
  ['reverse failure', { reverse: async () => { throw Error('NXDOMAIN'); } }],
  ['forward failure', { reverse: async () => ['crawl.googlebot.com'], lookup: async () => { throw Error('NXDOMAIN'); } }],
]) test(`good bot ${name} adds spoof risk`, async () => {
  const result = await localDecision(botState, { verifyBot: createGoodBotVerifier({ resolver }) });
  assert.equal(result.action, 'challenge'); assert.ok(result.reasons.includes('spoofed_good_bot'));
});
for (const stage of ['reverse', 'lookup']) test(`DNS ${stage} timeout never allows`, async () => {
  const resolver = { reverse: async () => ['crawl.googlebot.com'], lookup: async () => [{ address: botState.ip }] };
  resolver[stage] = () => new Promise(() => {});
  const start = Date.now();
  const result = await localDecision(botState, { verifyBot: createGoodBotVerifier({ resolver }) });
  assert.ok(Date.now() - start < 1000); assert.equal(result.action, 'challenge'); assert.ok(result.reasons.includes('good_bot_dns_timeout'));
});
test('DNS cache includes bot identity and expires at one hour', async () => {
  let now = 0, calls = 0;
  const verify = createGoodBotVerifier({ now: () => now, resolver: { reverse: async () => { calls++; return ['crawl.googlebot.com']; }, lookup: async () => [{ address: botState.ip }] } });
  assert.equal(await verify(botState), 'verified'); assert.equal(await verify(botState), 'verified'); assert.equal(calls, 1);
  assert.equal(await verify({ ...botState, ua: 'bingbot' }), 'failed'); assert.equal(calls, 2);
  now = 3600000; assert.equal(await verify(botState), 'verified'); assert.equal(calls, 3);
  assert.equal(await verify({ ua: chrome }), null); assert.equal(await verify({ ua: 'Googlebot' }), 'failed');
});
test('IPv6 forward confirmation compares canonical addresses', async () => {
  const verify = createGoodBotVerifier({ resolver: { reverse: async () => ['crawl.googlebot.com'], lookup: async () => [{ address: '2001:db8::1' }] } });
  assert.equal(await verify({ ua: 'Googlebot', ip: '2001:0db8:0:0:0:0:0:1' }), 'verified');
});

for (const brand of ['"Chromium";v="129"', '"Firefox";v="130"', '"Safari";v="18"']) test(`contradictory browser hint ${brand}`, () => {
  assert.ok(localHeuristic({ ua: chrome, headers: { ...headers(chrome), 'sec-ch-ua': brand } }).reasons.includes('ua_client_hint_mismatch'));
});
test('failed verification is cached for an hour too', async () => {
  let calls = 0;
  const verify = createGoodBotVerifier({ resolver: { reverse: async () => { calls++; throw Error('NXDOMAIN'); } } });
  assert.equal(await verify(botState), 'failed'); assert.equal(await verify(botState), 'failed'); assert.equal(calls, 1);
});
test('late DNS completion cannot turn a timeout into cached allow', async () => {
  let finish;
  const verify = createGoodBotVerifier({ timeoutMs: 5, resolver: { reverse: () => new Promise(resolve => { finish = resolve; }), lookup: async () => [{ address: botState.ip }] } });
  assert.equal(await verify(botState), 'timeout');
  finish(['crawl.googlebot.com']);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(await verify(botState), 'timeout');
});
