import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { createDecisionLog } from '../src/metering/decisions.js';
import { createMetrics } from '../src/metering/metrics.js';
import { createApp } from '../src/server.js';
import { createRateLimiter } from '../src/middleware/rateLimit.js';

async function temporary(fn) {
  const dir = await mkdtemp(join(tmpdir(), 'verdict-ops-'));
  try { await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}
const record = { action: 'allow', path: '/café' };
test('retention bounds concurrent UTF-8 appends and skips oversized records', () => temporary(async dir => {
  const file = join(dir, 'decisions.jsonl');
  const log = createDecisionLog(file, { maxBytes: 300, maxAgeDays: 0 });
  await Promise.all(Array.from({ length: 30 }, (_, i) => log({ ...record, request_id: String(i) })));
  assert.ok((await stat(file)).size <= 300);
  const rows = (await readFile(file, 'utf8')).trim().split('\n').map(JSON.parse);
  assert.equal(rows.at(-1).request_id, '29');
  await log({ ...record, reason: 'x'.repeat(400) });
  assert.ok((await stat(file)).size <= 300);
}));
test('age retention uses oldest timestamp across restarts and truncates at boundary', () => temporary(async dir => {
  const file = join(dir, 'decisions.jsonl');
  let time = 1000000000;
  const options = { maxBytes: 0, maxAgeDays: 7, now: () => time };
  await createDecisionLog(file, options)({ ...record, request_id: 'old' });
  time += 6 * 86400000;
  const log = createDecisionLog(file, options);
  await log({ ...record, request_id: 'recent' });
  assert.equal((await readFile(file, 'utf8')).trim().split('\n').length, 2);
  time += 86400000;
  await log({ ...record, request_id: 'new' });
  assert.equal(JSON.parse(await readFile(file, 'utf8')).request_id, 'new');
}));
test('retention validates configuration', () => {
  for (const options of [{ maxBytes: -1 }, { maxBytes: NaN }, { maxAgeDays: Infinity }]) assert.throws(() => createDecisionLog('unused', options));
});
test('metrics retain bounded recent latency histograms and lifetime totals', () => {
  const metrics = createMetrics({ capacity: 4 });
  assert.equal(metrics.snapshot().endpoints['/v1/decide'].latency_ms.p50, null);
  for (const value of [1000, 1, 2, 3, 4]) metrics.observe('/v1/decide', value);
  metrics.observe('/health', 1);
  for (const action of ['allow', 'allow', 'challenge', 'block', 'invalid']) metrics.decision(action);
  const snapshot = metrics.snapshot();
  assert.equal(snapshot.requests_total, 6);
  assert.deepEqual(snapshot.actions, { allow: 2, challenge: 1, block: 1 });
  const endpoint = snapshot.endpoints['/v1/decide'];
  assert.equal(endpoint.requests_total, 5);
  assert.equal(endpoint.latency_ms.samples, 4);
  assert.equal(endpoint.latency_ms.p50, 2);
  assert.equal(endpoint.latency_ms.p99, 4);
  assert.equal(endpoint.latency_ms.buckets['5'], 4);
  assert.equal(snapshot.endpoints['/v1/edge-auth'].requests_total, 0);
});
test('metrics are public, accept bearer, count errors and decisions; health matches package', () => temporary(async dir => {
  const app = await createApp({ keyFile: join(dir, 'keys.json'), usageFile: join(dir, 'usage.json'), rateLimit: createRateLimiter({ max: 1 }) });
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${base}/v1/decide`, { method: 'POST' })).status, 401);
    await fetch(`${base}/v1/edge-auth`, { headers: { 'user-agent': 'sqlmap' } });
    for (const headers of [{}, { authorization: 'Bearer example' }]) {
      const response = await fetch(`${base}/metrics`, { headers });
      assert.equal(response.status, 200);
      const data = await response.json();
      assert.equal(data.actions.block, 1);
      assert.equal(data.endpoints['/v1/decide'].requests_total, 1);
      assert.equal(data.endpoints['/v1/edge-auth'].latency_ms.samples, 1);
    }
    const key = await (await fetch(`${base}/v1/keys`, { method: 'POST' })).json();
    const options = { method: 'POST', headers: { authorization: `Bearer ${key.key}`, 'content-type': 'application/json' }, body: '{}' };
    for (const status of [200, 429]) {
      const response = await fetch(`${base}/v1/decide`, options);
      assert.equal(response.status, status);
      for (const prefix of ['x-ratelimit', 'x-ip-ratelimit']) {
        for (const suffix of ['limit', 'remaining', 'reset']) assert.ok(response.headers.has(`${prefix}-${suffix}`));
      }
      if (status === 429) assert.ok(response.headers.has('retry-after'));
    }
    const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url)));
    assert.equal((await (await fetch(`${base}/health`)).json()).version, pkg.version);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await app.locals.flush(); }
}));
test('key CLI creates once, lists metadata, and persists revocation', () => temporary(async dir => {
  const env = { ...process.env, VERDICT_KEY_FILE: join(dir, 'keys.json') };
  const run = (...args) => execFileSync(process.execPath, ['bin/verdict-keys.js', ...args], { env, encoding: 'utf8' }).trim();
  const key = run('create', 'ops');
  assert.match(key, /^vd_[\w-]+$/);
  const [entry] = JSON.parse(run('list'));
  assert.deepEqual(Object.keys(entry).sort(), ['created_at', 'id', 'name', 'revoked_at', 'scope']);
  assert.equal(entry.name, 'ops');
  assert.ok(!(await readFile(env.VERDICT_KEY_FILE, 'utf8')).includes(key));
  run('revoke', entry.id);
  assert.ok(JSON.parse(run('list'))[0].revoked_at);
}));
test('load test refuses public targets before sending requests', () => {
  for (const TARGET of ['http://example.com', 'http://192.0.2.1', 'http://127.0.0.1@evil.test']) {
    assert.throws(() => execFileSync(process.execPath, ['scripts/load-test.js'], { env: { ...process.env, TARGET }, stdio: 'pipe' }), /loopback/);
  }
});
