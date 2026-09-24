import { Router } from 'express';
import { env } from '../lib/config.js';
import { createZone, nsInstructions, issueCredential, mapHost } from './store.js';

export function onboardRouter({ reloadRoutes, staticRouteForHost }) {
  const router = Router();
  router.use((req, res, next) => {
    const expected = env('AGENT_TOKEN', 'fastdog-local-dev-token');
    if (req.headers['x-fastdog-token'] !== expected && req.body?.token !== expected) return res.status(401).json({ error: 'unauthorized' });
    next();
  });
  const handle = (fn) => (req, res) => {
    try { const result = fn(req); res.status(req.method === 'POST' ? 201 : 200).json(result); }
    catch (error) { res.status(error.status || 500).json({ error: error.message }); }
  };
  router.post('/zones', handle((req) => createZone(req.body || {})));
  router.get('/zones/:zone/ns-instructions', handle((req) => nsInstructions(req.params.zone)));
  router.post('/credentials', handle((req) => issueCredential(req.body || {})));
  router.post('/hosts', handle((req) => {
    const host = String(req.body?.hostname || '').toLowerCase();
    if (staticRouteForHost(host)) throw Object.assign(new Error('static_route_conflict'), { status: 409 });
    const result = mapHost(req.body || {});
    reloadRoutes();
    return result;
  }));
  return router;
}
