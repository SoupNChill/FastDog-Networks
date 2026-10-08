import { localHeuristic } from '../engine/heuristic.js';
import { lookupAsn } from '../asn/lookup.js';
import { createDecisionLog } from '../metering/decisions.js';

export function scoreAccessLogLine(line, { hosting } = {}) {
  let row;
  try { row = typeof line === 'string' ? JSON.parse(line) : line; } catch { return null; }
  const host = String(row.host || row.request?.host || '').toLowerCase();
  const allowed = new Set(['fastdognetworks.com', 'www.fastdognetworks.com', 'verdict-demo.fastdognetworks.com']);
  if (!allowed.has(host)) return null;
  const req = row.request || {};
  const ip = row.client_ip || row.remote_ip || row.request?.client_ip || '';
  const ua = req.headers?.['User-Agent'] || req.headers?.['user-agent'] || row.headers?.['User-Agent'] || '';
  const path = req.uri || req.url || row.uri || '/';
  const method = req.method || row.method || 'GET';
  const headers = {};
  const rawHeaders = req.headers || row.headers || {};
  for (const [k, v] of Object.entries(rawHeaders)) headers[String(k).toLowerCase()] = String(v);
  const asnInfo = ip ? lookupAsn(ip) : null;
  const state = {
    ip, path, method, ua, headers,
    asn: asnInfo?.asn,
    asn_name: asnInfo?.as_name,
    hosting_asn: hosting && asnInfo ? hosting.has(asnInfo.asn) : false,
  };
  const decision = localHeuristic(state);
  return {
    ts: row.ts || new Date().toISOString(),
    host,
    ip,
    path,
    method,
    ua: String(ua).slice(0, 200),
    action: decision.action,
    reason: decision.reason,
    reasons: decision.reasons,
    score: decision.score,
    engine: decision.engine,
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
