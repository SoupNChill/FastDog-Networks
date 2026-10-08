import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { Router } from 'express';
import { localHeuristic } from '../engine/heuristic.js';

export const cookieName = 'fd_verdict_clearance';
export function safeNext(value) {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//') && !/[\\\s\x00-\x1f\x7f]/.test(value) ? value : '/';
}
export function clientIP(req) {
  const forwarded = (req.get('x-forwarded-for') || req.get('x-real-ip') || '').split(',')[0].trim();
  return isIP(forwarded) ? forwarded : req.socket.remoteAddress;
}
const sign = (payload, secret) => createHmac('sha256', secret).update(payload).digest('base64url');
export function issueClearance(secret, ip = '*', ttl = 300, now = Date.now()) {
  const payload = `${Math.floor(now / 1000) + ttl}.${ip.toUpperCase()}`;
  return `${payload}.${sign(payload, secret)}`;
}
export function validClearance(token, secret, ip, now = Date.now()) {
  if (!secret || typeof token !== 'string') return false;
  const match = /^(\d+)\.(.+)\.([\w-]{43})$/.exec(token);
  if (!match) return false;
  const [, exp, bound, signature] = match;
  if (Number(exp) <= Math.floor(now / 1000) || (bound !== '*' && bound !== ip?.toUpperCase())) return false;
  const expected = sign(`${exp}.${bound}`, secret);
  return timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}
export function edgeRouter({ secret, ttl = 300, demoForce = false, logDecision }) {
  const router = Router();
  const requireSecret = (_req, res, next) => secret ? next() : res.status(503).json({ error: 'clearance_unconfigured' });
  router.get('/challenge', requireSecret, (_req, res) => {
    res.set('Cache-Control', 'no-store').type('html').send(`<!doctype html><html><head><meta charset="utf-8"><title>Verdict demo challenge</title></head><body><p id="status">Checking your browser…</p><script>
(async () => {
  const value = new URLSearchParams(location.search).get('next') || '/';
  const next = value.startsWith('/') && !value.startsWith('//') && !/[\\\\\\s\\x00-\\x1f\\x7f]/.test(value) ? value : '/';
  try {
    const response = await fetch('/challenge/verify', {method: 'POST'});
    if (!response.ok) throw new Error('Verification unavailable');
    location.replace(next);
  } catch (error) { document.getElementById('status').textContent = 'Verification unavailable. Please retry.'; }
})();</script></body></html>`);
  });
  router.post('/challenge/verify', requireSecret, (req, res) => {
    const token = issueClearance(secret, clientIP(req), ttl);
    res.set('Cache-Control', 'no-store');
    res.set('Set-Cookie', `${cookieName}=${token}; Path=/; Max-Age=${ttl}; HttpOnly; Secure; SameSite=Lax`);
    res.json({ ok: true });
  });
  router.get('/v1/edge-auth', async (req, res, next) => {
    try {
      const ip = clientIP(req);
      const token = (req.get('cookie') || '').split(';').map(value => value.trim()).find(value => value.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
      const path = req.get('x-forwarded-uri') || req.get('x-original-uri') || '/';
      let decision;
      if (validClearance(token, secret, ip)) decision = { action: 'allow', reason: 'valid_clearance', engine: 'clearance' };
      else {
        decision = localHeuristic({ ip, path, ua: req.get('user-agent'), method: req.get('x-forwarded-method') || req.get('x-original-method') || req.method });
        const forced = req.get('x-verdict-force');
        if (demoForce && ['allow', 'challenge', 'block'].includes(forced)) decision = { ...decision, action: forced, reason: 'demo_force' };
      }
      const request_id = randomUUID();
      await logDecision({ ...decision, request_id, ip, path });
      const status = { allow: 200, challenge: 401, block: 403 }[decision.action];
      res.set({ 'X-Verdict-Action': decision.action, 'Cache-Control': 'no-store' });
      if (decision.action === 'challenge') res.set('Location', `/challenge?next=${encodeURIComponent(safeNext(path))}`);
      if ((req.get('accept') || '').includes('application/json')) return res.status(status).json({ ...decision, request_id });
      res.status(status).end();
    } catch (error) { next(error); }
  });
  return router;
}
