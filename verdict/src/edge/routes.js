import { isEnforceDenied } from '../config/hosts.js';
import { randomUUID } from 'node:crypto';
import { binding, clientIP, validClearance, seal, DEMO_HOST, isLoopbackAddr } from './security.js';
import { challengeRouter } from './challenge.js';
import { Router } from 'express';
import { localDecision, localHeuristic } from '../engine/heuristic.js';
import { lookupAsn } from '../asn/lookup.js';
import { loadHostingAsns } from '../asn/lookup.js';

let hostingList;
function hosting() {
  if (!hostingList) {
    try { hostingList = loadHostingAsns(); } catch { hostingList = { has: () => false }; }
  }
  return hostingList;
}

// Initialize the small static ASN set before handling requests.
hosting();

export const cookieName = 'fd_verdict_clearance';
export function safeNext(value) {
  if (typeof value !== 'string') return '/';
  let v = value.trim();
  try { v = decodeURIComponent(v); } catch { /* keep */ }
  // Reject open redirects and encoded tricks
  if (!v.startsWith('/') || v.startsWith('//') || v.startsWith('/\\') || /[\\\s\x00-\x1f\x7f]/.test(v)) return '/';
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(v.slice(1))) return '/'; // /javascript:...
  if (v.toLowerCase().includes('%2f%2f') || v.toLowerCase().includes('%5c')) return '/';
  return v;
}
export { clientIP, issueClearance, validClearance } from './security.js';

function demoForceAllowed(req, demoForce) {
  if (!demoForce) return false;
  // Caddy alone injects X-Verdict-Demo: 1 on verdict-demo; strip client-sent elsewhere.
  return isLoopbackAddr(req.socket?.remoteAddress) && binding(req).host === DEMO_HOST && req.get('x-verdict-demo') === '1';
}

export function edgeRouter({ secret, ttl = 300, demoForce = false, edgeGoodBotDNS = false, logDecision, hostStore }) {
  const router = Router();
  router.use('/challenge', challengeRouter({ secret, ttl }));
  router.get('/v1/edge-auth', async (req, res, next) => {
    try {
      const bound = binding(req);
      if (!bound.host) return res.status(400).json({ error: 'invalid_host' });
      const config = hostStore?.get(bound.host);
      if (isEnforceDenied(bound.host) || (config && (!config.enable || config.mode !== 'enforce'))) {
        return res.set({ 'X-Verdict-Action': 'allow', 'Cache-Control': 'no-store' }).status(200).end();
      }
      const ip = clientIP(req);
      const token = (req.get('cookie') || '').split(';').map(value => value.trim()).find(value => value.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
      const path = req.get('x-forwarded-uri') || req.get('x-original-uri') || '/';
      let decision;
      if (validClearance(token, secret, binding(req))) decision = { action: 'allow', confidence: 1, score: 0, reason: 'valid_clearance', reasons: ['valid_clearance'], engine: 'clearance' };
      else {
        const asnInfo = lookupAsn(ip);
        const state = {
          ip, path, headers: req.headers, ua: req.get('user-agent'),
          method: req.get('x-forwarded-method') || req.get('x-original-method') || req.method,
          asn: asnInfo?.asn,
          asn_name: asnInfo?.as_name,
          hosting_asn: asnInfo ? hosting().has(asnInfo.asn) : false,
        };
        decision = edgeGoodBotDNS ? await localDecision(state) : localHeuristic(state, { goodBot: 'pending' });
      }
      let returnPath = safeNext(path);
      if (demoForceAllowed(req, demoForce)) {
        const original = new URL(returnPath, 'http://localhost');
        const forced = req.get('x-verdict-force') || original.searchParams.get('verdict');
        if (['allow', 'challenge', 'block'].includes(forced)) {
          decision = { ...decision, action: forced, reason: 'demo_force', reasons: [...(decision.reasons || []), 'demo_force'] };
          original.searchParams.delete('verdict');
          returnPath = safeNext(original.pathname + original.search);
        }
      }
      const request_id = randomUUID();
      logDecision({ ...decision, request_id, ip, path });
      const status = { allow: 200, challenge: 401, block: 403 }[decision.action];
      res.set({ 'X-Verdict-Action': decision.action, 'Cache-Control': 'no-store' });
      if (decision.action === 'challenge') {
        const hint = secret ? seal({ score: decision.score ?? decision.confidence, bound: binding(req), next: returnPath, exp: Date.now() + 120000 }, secret) : '';
        res.set('Location', `/challenge?next=${encodeURIComponent(returnPath)}&hint=${encodeURIComponent(hint)}`);
      }
      if ((req.get('accept') || '').includes('application/json')) return res.status(status).json({ ...decision, request_id });
      res.status(status).end();
    } catch (error) { next(error); }
  });
  return router;
}
