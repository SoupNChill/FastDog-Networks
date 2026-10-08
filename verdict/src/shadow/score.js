import { localHeuristic } from '../engine/heuristic.js';
import { lookupAsn } from '../asn/lookup.js';
import { createDecisionLog } from '../metering/decisions.js';
import { ipPrefix } from '../edge/security.js';

export function scoreAccessLogLine(line, { hosting } = {}) {
  let row;
  try { row = typeof line === 'string' ? JSON.parse(line) : line; } catch { return null; }
  const host = String(row.host || row.request?.host || '').toLowerCase();
  const allowed = new Set(['fastdognetworks.com', 'www.fastdognetworks.com', 'verdict-demo.fastdognetworks.com']);
  if (!allowed.has(host)) return null;
  const req = row.request || {};
  const ip = row.client_ip || row.remote_ip || row.request?.client_ip || '';
  const one = v => Array.isArray(v) ? v.join(', ') : (v == null ? '' : String(v)); // Caddy logs header values as arrays
  const ua = one(req.headers?.['User-Agent'] ?? req.headers?.['user-agent'] ?? row.headers?.['User-Agent']);
  const path = req.uri || req.url || row.uri || '/';
  const method = req.method || row.method || 'GET';
  const headers = {};
  const rawHeaders = req.headers || row.headers || {};
  for (const [k, v] of Object.entries(rawHeaders)) headers[String(k).toLowerCase()] = one(v).slice(0, 2048);
  const asnInfo = ip ? lookupAsn(ip) : null;
  const state = {
    ip, path, method, ua, headers,
    asn: asnInfo?.asn,
    hosting_asn: hosting && asnInfo ? hosting.has(asnInfo.asn) : false,
  };
  const decision = localHeuristic(state);
  const ts = typeof row.ts === 'number' ? new Date(row.ts * 1000).toISOString() : (row.ts || new Date().toISOString());
  return {
    ts,
    host,
    ip_prefix: ipPrefix(ip) || null, // raw IP is never persisted
    path,
    method,
    ua: String(ua).slice(0, 200),
    action: decision.action,
    reason: decision.reason,
    reasons: decision.reasons,
    score: decision.score,
    engine: decision.engine,
    asn: asnInfo?.asn ?? null,
    shadow: true,
  };
}

export function createShadowWriter(file, opts) {
  return createDecisionLog(file, {
    maxBytes: Number(process.env.VERDICT_SHADOW_MAX_BYTES ?? 10 * 1024 * 1024),
    maxAgeDays: Number(process.env.VERDICT_SHADOW_MAX_AGE_DAYS ?? 7),
    ...opts,
  });
}
