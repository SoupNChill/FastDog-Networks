import { verifyGoodBot } from '../engine/goodbots.js';
import { localHeuristic } from '../engine/heuristic.js';
import { lookupAsn } from '../asn/lookup.js';
export { createShadowWriter } from './retention.js';
import { ipPrefix } from '../edge/security.js';

export function scoreAccessLogLine(line, { hosting, allowedHosts, verifyBot = verifyGoodBot, dnsEnabled = process.env.VERDICT_EDGE_GOODBOT_DNS === '1' } = {}) {
  let row;
  try { row = typeof line === 'string' ? JSON.parse(line) : line; } catch { return null; }
  const host = String(row.host || row.request?.host || '').toLowerCase();
  const allowed = new Set(['fastdognetworks.com', 'www.fastdognetworks.com', 'verdict-demo.fastdognetworks.com']);
  if (!(allowedHosts || allowed).has(host)) return null;
  const req = row.request || {};
  const ip = row.client_ip || row.remote_ip || row.request?.client_ip || '';
  const one = v => Array.isArray(v) ? v.join(', ') : (v == null ? '' : String(v)); // Caddy logs header values as arrays
  // Masked lines (Caddy filter encoder): no header context at all, client_ip already a /24 or /48,
  // UA moved to a top-level user_agent field.
  const masked = !req.headers && !row.headers;
  const ua = one(req.headers?.['User-Agent'] ?? req.headers?.['user-agent'] ?? row.headers?.['User-Agent'] ?? row.user_agent);
  const path = req.uri || req.url || row.uri || '/';
  const method = req.method || row.method || 'GET';
  let headers;
  if (!masked) {
    headers = {};
    for (const [k, v] of Object.entries(req.headers || row.headers)) headers[String(k).toLowerCase()] = one(v).slice(0, 2048);
  }
  const asnInfo = ip ? lookupAsn(ip) : null;
  const state = {
    ip, path, method, ua, headers,
    asn: asnInfo?.asn,
    hosting_asn: hosting && asnInfo ? hosting.has(asnInfo.asn) : false,
  };
  // Header signals are unknown (headers undefined), and a /24 is not one client, so no per-IP rate.
  if (masked) state.ip_velocity = false;
  const finish = goodBot => {
    const decision = localHeuristic(state, { goodBot });
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
  };
  const verified = verifyBot(state, { dnsEnabled });
  return verified?.then ? verified.then(finish) : finish(verified);
}
