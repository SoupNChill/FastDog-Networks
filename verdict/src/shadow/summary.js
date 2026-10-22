import { pruneShadowSummaries } from './retention.js';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { readdir, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';

// Persisted/emitted paths never carry a query string (rows written before 0.3.3 may still have one).
export const stripQuery = path => typeof path === 'string' ? path.split('?', 1)[0] : path;

export function redactIp(ip) {
  if (!ip || typeof ip !== 'string') return null;
  if (ip.includes(':')) {
    // IPv6 → /48 hash prefix
    return 'v6:' + createHash('sha256').update(ip).digest('hex').slice(0, 12);
  }
  const parts = ip.split('.');
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  return createHash('sha256').update(ip).digest('hex').slice(0, 12);
}

export function redactSample(row) {
  return {
    ts: row.ts,
    host: row.host,
    path: typeof row.path === 'string' ? stripQuery(row.path).slice(0, 120) : null,
    method: row.method,
    action: row.action,
    reason: row.reason,
    reasons: Array.isArray(row.reasons) ? row.reasons.slice(0, 12) : [],
    score: row.score,
    ip_redacted: row.ip_prefix || redactIp(row.ip),
    ua_class: classifyUa(row.ua),
  };
}

function classifyUa(ua = '') {
  const s = String(ua);
  if (/Googlebot/i.test(s)) return 'googlebot';
  if (/bingbot/i.test(s)) return 'bingbot';
  if (/curl\//i.test(s)) return 'curl';
  if (/python-requests/i.test(s)) return 'python-requests';
  if (/HeadlessChrome|Puppeteer|Selenium/i.test(s)) return 'headless';
  if (/Mobile|iPhone|Android/i.test(s)) return 'mobile_browser';
  if (/Chrome|Safari|Firefox|Edg\//i.test(s)) return 'desktop_browser';
  return 'other';
}

export async function buildShadowSummary(shadowFile, { day = new Date().toISOString().slice(0, 10), limitSamples = 10 } = {}) {
  const counts = { allow: 0, challenge: 0, block: 0, total: 0 };
  const reasonCounts = new Map();
  const samples = [];
  try {
    const rl = createInterface({ input: createReadStream(shadowFile, { encoding: 'utf8' }), crlfDelay: Infinity });
    for await (const line of rl) {
      if (!line.trim()) continue;
      let row;
      try { row = JSON.parse(line); } catch { continue; }
      if (row.ts && !String(row.ts).startsWith(day)) continue;
      counts.total++;
      if (Object.hasOwn(counts, row.action)) counts[row.action]++;
      for (const r of row.reasons || [row.reason].filter(Boolean)) {
        reasonCounts.set(r, (reasonCounts.get(r) || 0) + 1);
      }
      if ((row.action === 'challenge' || row.action === 'block') && samples.length < limitSamples) {
        samples.push(redactSample(row));
      }
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const top_reasons = [...reasonCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20)
    .map(([reason, count]) => ({ reason, count }));
  return {
    day,
    generated_at: new Date().toISOString(),
    counts,
    top_reasons,
    samples_would_challenge_or_block: samples,
    note: 'IPs redacted. Synthetic FP rates are not claimed here — this is live shadow observation only.',
  };
}

export async function writeShadowSummary(shadowFile, outDir = 'data') {
  const day = new Date().toISOString().slice(0, 10);
  const summary = await buildShadowSummary(shadowFile, { day });
  await mkdir(outDir, { recursive: true });
  const out = join(outDir, `shadow-summary-${day.replace(/-/g, '')}.json`);
  await writeFile(out, JSON.stringify(summary, null, 2), { mode: 0o600 });
  await pruneShadowSummaries(outDir);
  return { out, summary };
}
