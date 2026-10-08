import { randomUUID } from 'node:crypto';
import { structuredSignals } from './signals.js';
import { claimedGoodBot, verifyGoodBot } from './goodbots.js';
const velocity = new Map();
const asnVelocity = new Map();
export const resetVelocity = () => { velocity.clear(); asnVelocity.clear(); };
function count(map, key, now) {
  for (const [key, bucket] of map) if (now - bucket.start >= 60_000) map.delete(key);
  if (!map.has(key) && map.size >= 10000) return Infinity;
  const bucket = map.get(key) || { start: now, hits: 0 };
  bucket.hits++;
  map.set(key, bucket);
  return bucket.hits;
}
export function localHeuristic(input, { now = Date.now(), goodBot } = {}) {
  const state = input && typeof input === 'object' ? input : {};
  const engine = 'local_heuristic_v3';
  const request_id = randomUUID();
  if (goodBot === 'verified') return { action: 'allow', confidence: 1, score: 0, reason: 'verified_good_bot', reasons: ['verified_good_bot'], engine, request_id };
  const fired = structuredSignals(state);
  if (claimedGoodBot(state)) fired.push({ id: goodBot === 'pending' ? 'good_bot_pending' : goodBot === 'timeout' ? 'good_bot_dns_timeout' : 'spoofed_good_bot', weight: 0.35 });
  if (typeof state.ip === 'string' && state.ip && count(velocity, state.ip, now) > 30) fired.push({ id: 'ip_velocity', weight: 0.2 });
  if (state.hosting_asn && goodBot !== 'verified') fired.push({ id: 'datacenter_asn', weight: 0.12 });
  const asn = String(state.asn ?? '').trim().replace(/^AS/i, '');
  if (/^\d+$/.test(asn) && count(asnVelocity, String(Number(asn)), now) > 300) fired.push({ id: 'asn_velocity', weight: 0.2 });
  const score = Math.min(0.99, Number((0.2 + fired.reduce((sum, signal) => sum + signal.weight, 0)).toFixed(6)));
  const action = score >= 0.75 ? 'block' : score >= 0.45 ? 'challenge' : 'allow';
  return { action, confidence: action === 'allow' ? 1 - score : score, score,
    reason: action === 'block' ? 'high_risk_signals' : action === 'challenge' ? 'ambiguous_automation' : 'low_risk',
    reasons: fired.map(signal => signal.id), engine, request_id };
}
export async function localDecision(state, { verifyBot = verifyGoodBot, ...options } = {}) {
  return localHeuristic(state, { ...options, goodBot: claimedGoodBot(state) ? await verifyBot(state) : null });
}
