import { promisify } from 'node:util';
import test from 'node:test';
import assert from 'node:assert/strict';
import { promises as dns } from 'node:dns';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile, execFileSync } from 'node:child_process';
import { createApp } from '../src/server.js';
import { createMeter } from '../src/metering/usage.js';
import { issueClearance } from '../src/edge/security.js';
import { replayFixtures } from '../scripts/replay-fixtures.js';

async function serve(options, fn) {
  const dir = await mkdtemp(join(tmpdir(), 'verdict-polish-'));
  const app = await createApp({ keyFile: join(dir, 'keys.json'), usageFile: join(dir, 'usage.json'), ...options });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try { await fn(`http://127.0.0.1:${server.address().port}`, app); }
  finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await app.locals.flush();
    await rm(dir, { recursive: true, force: true });
  }
}
const post = (url, body, key) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) }, body: JSON.stringify(body), signal: AbortSignal.timeout(1000) });

test('stalled decision writer cannot delay either response; metrics remain immediate', async () => {
  let release;
  const stalled = new Promise(resolve => { release = resolve; });
  let calls = 0;
  try {
    await serve({ decisionWriter: () => { calls++; return stalled; } }, async (base) => {
      const { key } = await (await post(base + '/v1/keys', {})).json();
      assert.equal((await fetch(base + '/v1/edge-auth', { signal: AbortSignal.timeout(1000) })).status, 200);
      assert.equal((await post(base + '/v1/decide', {}, key)).status, 200);
      assert.equal(calls, 2);
      assert.equal((await (await fetch(base + '/metrics')).json()).actions.allow, 2);
    });
  } finally { release(); }
});

test('non-bots never use dns.promises; edge bot claims skip DNS by default and opt-in verifies', async t => {
  let reverseCalls = 0, lookupCalls = 0;
  t.mock.method(dns, 'reverse', async () => { reverseCalls++; return ['crawl.googlebot.com']; });
  t.mock.method(dns, 'lookup', async () => { lookupCalls++; return [{ address: '192.0.2.240' }]; });
  const botHeaders = { 'user-agent': 'Googlebot/2.1', 'x-forwarded-for': '192.0.2.240', accept: 'application/json' };
  await serve({ edgeGoodBotDNS: false }, async base => {
    assert.equal((await fetch(base + '/v1/edge-auth', { headers: { 'user-agent': 'Mozilla/5.0' } })).status, 200);
    const { key } = await (await post(base + '/v1/keys', {})).json();
    assert.equal((await post(base + '/v1/decide', { ua: 'curl/8.7.1' }, key)).status, 200);
    const result = await fetch(base + '/v1/edge-auth', { headers: botHeaders });
    assert.equal(result.status, 401);
    assert.ok((await result.json()).reasons.includes('good_bot_pending'));
    assert.equal(reverseCalls + lookupCalls, 0);
  });
  await serve({ edgeGoodBotDNS: true }, async base => {
    assert.equal((await fetch(base + '/v1/edge-auth', { headers: botHeaders })).status, 200);
    assert.equal(reverseCalls, 1); assert.equal(lookupCalls, 1);
  });
});

for (const demoForce of [false, true]) test(`demo queries and headers, enabled=${demoForce}`, () => serve({ demoForce, clearanceSecret: 'test-secret' }, async base => {
  const headers = { 'user-agent': 'Mozilla/5.0', 'x-forwarded-host': 'shop.example', 'x-forwarded-for': '192.0.2.241', 'accept-language': 'en-US' };
  const cookie = `fd_verdict_clearance=${issueClearance('test-secret', { host: 'shop.example', ip: '192.0.2.241', ua: headers['user-agent'] })}`;
  for (const uriHeader of ['x-forwarded-uri', 'x-original-uri']) {
    for (const [action, status] of [['allow', 200], ['challenge', 401], ['block', 403]]) {
      const response = await fetch(base + '/v1/edge-auth', { headers: { ...headers, cookie, [uriHeader]: `/?keep=yes&verdict=${action}` } });
      assert.equal(response.status, demoForce ? status : 200);
      if (demoForce && action === 'challenge') {
        const url = new URL(response.headers.get('location'), base);
        assert.equal(url.searchParams.get('next'), '/?keep=yes');
      }
    }
  }
  assert.equal((await fetch(base + '/v1/edge-auth', { headers: { ...headers, 'x-verdict-force': 'block', 'x-forwarded-uri': '/?verdict=allow' } })).status, demoForce ? 403 : 200);
  assert.equal((await fetch(base + '/v1/edge-auth', { headers: { ...headers, 'x-forwarded-uri': '/?verdict=invalid' } })).status, 200);
  const page = await (await fetch(base + '/demo')).text();
  assert.match(page, /FastDog/);
  assert.equal(page.includes('href="/?verdict=challenge"'), demoForce);
}));

test('usage records are immediate in memory and batch to one snapshot', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'verdict-meter-'));
  const file = join(dir, 'usage.json');
  try {
    const meter = createMeter({ file });
    await meter.load();
    for (let i = 0; i < 100; i++) assert.equal(meter.record('key', 'local'), undefined);
    assert.equal(meter.get('key').decisions, 100);
    await assert.rejects(readFile(file), { code: 'ENOENT' });
    await meter.ready();
    assert.equal(JSON.parse(await readFile(file)).key.decisions, 100);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('large fixture suite meets FP/FN budgets', async () => {
  const report = await replayFixtures();
  assert.ok(report.good.total >= 500 && report.bad.total >= 200);
  assert.ok(report.fp_rate <= 0.01 && report.fn_rate <= 0.05);
});

test('steady-rate load refuses non-loopback targets and unsafe paths before requests', () => {
  for (const env of [{ TARGET: 'http://example.com' }, { TARGET: 'http://192.0.2.1' }, { TARGET: 'http://127.0.0.1@evil.test' }, { PATHS: '//example.com' }]) {
    assert.throws(() => execFileSync(process.execPath, ['scripts/load-step.js'], { env: { ...process.env, TARGET: 'http://127.0.0.1:8089', ...env }, stdio: 'pipe' }), /loopback|PATHS/);
  }
});


test('steady-rate load produces loopback JSON for both endpoints', () => serve({}, async base => {
  const { key } = await (await post(base + '/v1/keys', {})).json();
  const { stdout } = await promisify(execFile)(process.execPath, ['scripts/load-step.js'], {
    env: { ...process.env, TARGET: base, RPS: '20', SECONDS: '1', PATHS: '/v1/edge-auth,/v1/decide', VERDICT_API_KEY: key },
  });
  const report = JSON.parse(stdout);
  assert.equal(report.rps_target, 20);
  assert.ok(report.requests >= 10 && report.requests <= 20);
  assert.equal(report.errors, 0);
  assert.equal(report.statuses['200'], report.requests);
  assert.ok(report.p99 >= report.p50 && report.p50 > 0);
}));

test('rejected log writes are reported without failing responses', async t => {
  const errors = [];
  t.mock.method(console, 'error', (...args) => errors.push(args.join(' ')));
  await serve({ decisionWriter: async () => { throw Error('test disk failure'); } }, async base => {
    const { key } = await (await post(base + '/v1/keys', {})).json();
    assert.equal((await fetch(base + '/v1/edge-auth')).status, 200);
    assert.equal((await post(base + '/v1/decide', {}, key)).status, 200);
    assert.equal(errors.filter(line => line.includes('test disk failure')).length, 2);
  });
});
