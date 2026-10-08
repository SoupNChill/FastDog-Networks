import { isIP } from 'node:net';
import { isLoopback } from '../src/auth/keys.js';

try {
  const target = new URL(process.env.TARGET || `http://127.0.0.1:${process.env.PORT || 8080}`);
  const host = target.hostname.replace(/^\[|\]$/g, '');
  if (target.protocol !== 'http:' || !isIP(host) || !isLoopback(host) || target.username || target.password || target.pathname !== '/' || target.search || target.hash) {
    throw new Error('Target must be a literal loopback HTTP origin; hostnames and redirects are forbidden');
  }
  const concurrency = Number(process.env.CONCURRENCY || 50);
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 200) throw new Error('CONCURRENCY must be 1–200');
  if (!process.env.VERDICT_API_KEY) throw new Error('Set VERDICT_API_KEY for the local test server');
  const results = Object.fromEntries(['/v1/decide', '/v1/edge-auth'].map(path => [path, { total: 0, errors: 0, statuses: {}, latencies: new Float64Array(2048), count: 0 }]));
  const start = performance.now();
  const deadline = start + 30000;
  let sequence = 0;
  await Promise.all(Array.from({ length: concurrency }, async () => {
    while (performance.now() < deadline) {
      const path = sequence++ % 2 ? '/v1/edge-auth' : '/v1/decide';
      const result = results[path];
      const began = performance.now();
      try {
        const response = await fetch(new URL(path, target), {
          method: path === '/v1/decide' ? 'POST' : 'GET', redirect: 'error',
          headers: { authorization: `Bearer ${process.env.VERDICT_API_KEY}`, 'content-type': 'application/json', 'user-agent': 'Mozilla/5.0' },
          ...(path === '/v1/decide' ? { body: JSON.stringify({ path: '/', ua: 'Mozilla/5.0' }) } : {}),
          signal: AbortSignal.timeout(Math.max(1, Math.ceil(deadline - performance.now()))),
        });
        await response.arrayBuffer();
        result.statuses[response.status] = (result.statuses[response.status] || 0) + 1;
      } catch { result.errors++; }
      result.latencies[result.total % 2048] = performance.now() - began;
      result.total++;
      result.count = Math.min(result.total, 2048);
    }
  }));
  const seconds = (performance.now() - start) / 1000;
  for (const [path, result] of Object.entries(results)) {
    const sorted = Array.from(result.latencies.subarray(0, result.count)).sort((a, b) => a - b);
    console.log(JSON.stringify({ path, seconds, concurrency, requests: result.total, rps: result.total / seconds, p50_ms: sorted[Math.ceil(sorted.length * 0.5) - 1] ?? null, p99_ms: sorted[Math.ceil(sorted.length * 0.99) - 1] ?? null, latency_samples: result.count, errors: result.errors, statuses: result.statuses }));
  }
} catch (error) { console.error(error.message); process.exitCode = 1; }
