import { randomUUID } from 'node:crypto';
import { binding, clientIP, validClearance, seal } from './security.js';
import { challengeRouter } from './challenge.js';
import { Router } from 'express';
import { localDecision, localHeuristic } from '../engine/heuristic.js';

export const cookieName = 'fd_verdict_clearance';
export function safeNext(value) {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') && !/[\\\s\x00-\x1f\x7f]/.test(value) ? value : '/';
}
export { clientIP, issueClearance, validClearance } from './security.js';
export function edgeRouter({ secret, ttl = 300, demoForce = false, edgeGoodBotDNS = false, logDecision }) {
  const router = Router();
  router.use('/challenge', challengeRouter({ secret, ttl }));
  router.get('/v1/edge-auth', async (req, res, next) => {
    try {
      const ip = clientIP(req);
      const token = (req.get('cookie') || '').split(';').map(value => value.trim()).find(value => value.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
      const path = req.get('x-forwarded-uri') || req.get('x-original-uri') || '/';
      let decision;
      if (validClearance(token, secret, binding(req))) decision = { action: 'allow', confidence: 1, score: 0, reason: 'valid_clearance', reasons: ['valid_clearance'], engine: 'clearance' };
      else {
        const state = { ip, path, headers: req.headers, ua: req.get('user-agent'), method: req.get('x-forwarded-method') || req.get('x-original-method') || req.method };
        decision = edgeGoodBotDNS ? await localDecision(state) : localHeuristic(state, { goodBot: 'pending' });
      }
      let returnPath = safeNext(path);
      if (demoForce) {
        const original = new URL(returnPath, 'http://localhost');
        const forced = req.get('x-verdict-force') || original.searchParams.get('verdict');
        if (['allow', 'challenge', 'block'].includes(forced)) {
          decision = { ...decision, action: forced, reason: 'demo_force', reasons: [...decision.reasons, 'demo_force'] };
          // A solved challenge must not redirect back into the forced challenge.
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
