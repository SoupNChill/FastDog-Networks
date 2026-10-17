import { trafficStats, shadowStats, certInfo, testSite, liveState } from './site-status.js';
import { fail } from './claims.js';

const MINUTE = 60000;

// Wraps the probes with ownership checks (via agent(), which throws for a hostname the tenant does
// not hold as an active claim), a short cache, and rate limits for the on-demand test.
export function createSiteStatus(opts = {}) {
  const now = opts.now ?? Date.now;
  const probes = { trafficStats, shadowStats, certInfo, testSite, ...opts.siteProbes };
  const env = opts.env ?? process.env;
  const [tlsHost, tlsPortRaw] = String(opts.statusTlsAddr ?? env.STATUS_TLS_ADDR ?? '127.0.0.1:443').split(/:(?=\d+$)/);
  const tlsPort = Number(tlsPortRaw || 443);
  if (!['127.0.0.1', '::1', 'localhost'].includes(tlsHost) || !Number.isInteger(tlsPort) || tlsPort < 1 || tlsPort > 65535) {
    throw new Error('STATUS_TLS_ADDR must be a loopback address');
  }
  const logDir = opts.accessLogDir ?? env.FASTDOG_ACCESS_LOG_DIR ?? '/var/log/caddy';
  const shadowFile = opts.shadowFile ?? env.VERDICT_SHADOW_FILE ?? '/opt/verdict/data/shadow.jsonl';
  const countsFile = opts.countsFile ?? env.VERDICT_SHADOW_COUNTS_FILE ?? '/var/lib/verdict-shadow/customer-counts.json';
  const cache = new Map();
  const limits = new Map();
  function limit(key, count, windowMs) {
    const time = now();
    for (const [k, v] of limits) if (v.until <= time) limits.delete(k);
    const value = limits.get(key) ?? { count: 0, until: time + windowMs };
    if (value.count >= count) throw fail(429, 'rate_limited', { retry_after: Math.ceil((value.until - time) / 1000) });
    value.count++;
    limits.set(key, value);
  }
  async function status(tid, host) {
    const agent = opts.agent(tid, host);
    // Activation time of this tenant's current claim; probes fail closed without a usable one.
    const since = opts.claimSince?.(tid, host) ?? null;
    const key = `${tid}:${host}:${since}`;
    const hit = cache.get(key);
    let probed = hit && hit.until > now() ? hit.value : null;
    if (!probed) {
      const [traffic, shadow, cert] = await Promise.all([
        probes.trafficStats(host, { logDir, since, now }).catch(() => ({ available: false })),
        probes.shadowStats(host, { shadowFile, countsFile, since, now }).catch(() => ({ available: false, shadow: true })),
        probes.certInfo(host, { tlsHost, tlsPort, timeout: 2500 }).catch(() => null),
      ]);
      probed = { traffic, shadow, cert, checked_at: new Date(now()).toISOString() };
      for (const [k, v] of cache) if (v.until <= now()) cache.delete(k);
      cache.set(key, { value: probed, until: now() + 30000 });
    }
    return { hostname: host, ...liveState({ agent, cert: probed.cert, now }), checked_at: probed.checked_at,
      agent, cert: probed.cert, traffic: probed.traffic, verdict: probed.shadow };
  }
  async function test(tid, host) {
    opts.agent(tid, host);
    limit(`test:${tid}`, 10, MINUTE);
    limit(`test-host:${host}`, 30, 60 * MINUTE);
    const result = await probes.testSite(host, { tlsHost, tlsPort, timeout: 4000 });
    return { hostname: host, tested_at: new Date(now()).toISOString(),
      ok: Boolean(result.ok), status: Number.isInteger(result.status) ? result.status : null,
      ms: Number.isFinite(result.ms) ? result.ms : null, error: result.error ?? null, cert: result.cert ?? null };
  }
  return { status, test };
}
