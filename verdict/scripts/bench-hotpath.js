import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../src/server.js';
import { resetVelocity } from '../src/engine/heuristic.js';

// Never call the optional paid engine, even if inherited from the shell.
process.env.TYPESAFE_API_KEY = '';
const dir = await mkdtemp(join(tmpdir(), 'verdict-bench-'));
const pass = (_req, _res, next) => next();
const app = await createApp({ keyFile: join(dir, 'keys.json'), usageFile: join(dir, 'usage.json'), rateLimit: pass, ipRateLimit: pass, demoForce: false, edgeGoodBotDNS: false });
const server = app.listen(0, '127.0.0.1');
await new Promise(resolve => server.once('listening', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
try {
  const bootstrap = await fetch(`${base}/v1/keys`, { method: 'POST' });
  assert.equal(bootstrap.status, 201);
  const { key } = await bootstrap.json();
  for (const path of ['/v1/edge-auth', '/v1/decide']) {
    resetVelocity();
    const samples = [];
    for (let i = -100; i < 1000; i++) {
      const started = performance.now();
      const response = await fetch(base + path, {
        method: path.endsWith('decide') ? 'POST' : 'GET',
        headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', 'user-agent': 'Mozilla/5.0 Chrome/130.0.0.0', 'accept-language': 'en-US' },
        ...(path.endsWith('decide') ? { body: JSON.stringify({ path: '/login', method: 'GET', ua: 'Mozilla/5.0 Chrome/130.0.0.0', headers: { 'accept-language': 'en-US' } }) } : {}),
      });
      await response.arrayBuffer();
      assert.equal(response.status, 200);
      if (i >= 0) samples.push(performance.now() - started);
    }
    samples.sort((a, b) => a - b);
    const report = { path, requests: samples.length, p50_ms: samples[499], p99_ms: samples[989] };
    console.log(JSON.stringify(report));
    if (process.env.CI && report.p99_ms >= 25) console.warn('Noisy CI: p99 exceeded 25ms');
    else assert.ok(report.p99_ms < 25, `${path}: p99 must be <25ms (quiet-machine goal <15ms)`);
  }
} finally {
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  await app.locals.flush();
  await rm(dir, { recursive: true, force: true });
}
