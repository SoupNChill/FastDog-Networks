import { randomUUID } from 'node:crypto';
import { binding, clientIP, validClearance, seal } from './security.js';
import { challengeRouter } from './challenge.js';
import { Router } from 'express';
import { localDecision } from '../engine/heuristic.js';

export const cookieName = 'fd_verdict_clearance';
export function safeNext(value) {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') && !/[\\\s\x00-\x1f\x7f]/.test(value) ? value : '/';
}
export { clientIP, issueClearance, validClearance } from './security.js';
export function edgeRouter({ secret, ttl = 300, demoForce = false, logDecision }) {
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
        decision = await localDecision({ ip, path, headers: req.headers, ua: req.get('user-agent'), method: req.get('x-forwarded-method') || req.get('x-original-method') || req.method });
        const forced = req.get('x-verdict-force');
        if (demoForce && ['allow', 'challenge', 'block'].includes(forced)) decision = { ...decision, action: forced, reason: 'demo_force', reasons: [...decision.reasons, 'demo_force'] };
      }
      const request_id = randomUUID();
      await logDecision({ ...decision, request_id, ip, path });
      const status = { allow: 200, challenge: 401, block: 403 }[decision.action];
      res.set({ 'X-Verdict-Action': decision.action, 'Cache-Control': 'no-store' });
      if (decision.action === 'challenge') {
        const hint = secret ? seal({ score: decision.score ?? decision.confidence, bound: binding(req), next: safeNext(path), exp: Date.now() + 120000 }, secret) : '';
        res.set('Location', `/challenge?next=${encodeURIComponent(safeNext(path))}&hint=${encodeURIComponent(hint)}`);
      }
      if ((req.get('accept') || '').includes('application/json')) return res.status(status).json({ ...decision, request_id });
      res.status(status).end();
    } catch (error) { next(error); }
  });
  return router;
}
