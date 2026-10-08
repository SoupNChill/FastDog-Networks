import { isIP } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { isLoopback } from '../src/auth/keys.js';

try {
  const target = new URL(process.env.TARGET || 'http://127.0.0.1:8089');
  const host = target.hostname.replace(/^\[|\]$/g, '');
  if (target.protocol !== 'http:' || !isIP(host) || !isLoopback(host) || target.username || target.password || target.pathname !== '/' || target.search || target.hash) {
    throw new Error('Target must be a literal loopback HTTP origin; hostnames and redirects are forbidden');
  }
  const rps = Number(process.env.RPS || 100), seconds = Number(process.env.SECONDS || 30);
  if (!Number.isFinite(rps) || rps < 1 || rps > 10000 || !Number.isFinite(seconds) || seconds <= 0 || seconds > 3600 || rps * seconds > 1000000) throw new Error('Invalid RPS/SECONDS (maximum 1,000,000 requests)');
  const paths = (process.env.PATHS || '/v1/edge-auth').split(',');
  if (paths.some(path => !['/v1/edge-auth', '/v1/decide'].includes(path))) throw new Error('PATHS must contain /v1/edge-auth and/or /v1/decide');
  if (paths.includes('/v1/decide') && !process.env.VERDICT_API_KEY) throw new Error('VERDICT_API_KEY is required for decide');
  const samples = [], statuses = {}, pending = new Set();
  let errors = 0, sent = 0;
  const start = performance.now(), deadline = start + seconds * 1000;
  async function request(path) {
    const began = performance.now();
    try {
      const response = await fetch(new URL(path, target), {
        method: path.endsWith('decide') ? 'POST' : 'GET', redirect: 'error', signal: AbortSignal.timeout(5000),
        headers: { 'user-agent': 'Mozilla/5.0', 'accept-language': 'en-US', 'content-type': 'application/json', ...(process.env.VERDICT_API_KEY ? { authorization: `Bearer ${process.env.VERDICT_API_KEY}` } : {}) },
        ...(path.endsWith('decide') ? { body: JSON.stringify({ path: '/', method: 'GET', ua: 'Mozilla/5.0', headers: { 'accept-language': 'en-US' } }) } : {}),
      });
      await response.arrayBuffer();
      statuses[response.status] = (statuses[response.status] || 0) + 1;
      if (response.status >= 400) errors++;
    } catch { errors++; }
    samples.push(performance.now() - began);
  }
  // Absolute launch times prevent response latency from setting the offered rate.
  // Missed slots are skipped rather than emitted as a catch-up burst.
  const interval = 1000 / rps;
  for (let slot = 0; slot < rps * seconds; slot++) {
    const due = start + slot * interval;
    if (due > performance.now()) await sleep(due - performance.now());
    const now = performance.now();
    if (now >= deadline) break;
    if (now - due >= interval) { slot = Math.floor((now - start) / interval); }
    if (pending.size >= 2000) continue;
    const task = request(paths[sent++ % paths.length]);
    pending.add(task);
    task.finally(() => pending.delete(task));
  }
  if (performance.now() < deadline) await sleep(deadline - performance.now());
  await Promise.all(pending);
  samples.sort((a, b) => a - b);
  console.log(JSON.stringify({ rps_target: rps, rps_achieved: sent / seconds, seconds, requests: sent, p50: samples[Math.ceil(samples.length * 0.5) - 1] ?? null, p99: samples[Math.ceil(samples.length * 0.99) - 1] ?? null, latency_unit: 'ms', errors, statuses }));
} catch (error) { console.error(error.message); process.exitCode = 1; }
