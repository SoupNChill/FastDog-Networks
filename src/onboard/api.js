import { Router } from 'express';
import { env } from '../lib/config.js';
import { createZone, nsInstructions, issueCredential, mapHost } from './store.js';
import { generateInvite, listInvites, redeemInvite } from './invites.js';
import { attachHost, verifyHost, listAttachedHosts, detachHost, getAttachedHost } from './attach.js';

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
  const handleAsync = (fn, status = 200) => async (req, res) => {
    try { const result = await fn(req); res.status(status).json(result); }
    catch (error) { res.status(error.status || 500).json({ error: error.message }); }
  };
  router.post('/attach-host', handle((req) => {
    const host = String(req.body?.hostname || '').toLowerCase();
    if (staticRouteForHost(host)) throw Object.assign(new Error('static_route_conflict'), { status: 409 });
    return attachHost(req.body || {});
  }));
  router.post('/verify-host', handleAsync(async (req) => {
    const result = await verifyHost(req.body || {});
    if (result.verified) reloadRoutes();
    return result;
  }));
  router.get('/attached-hosts', handle(() => ({ hosts: listAttachedHosts() })));
  router.get('/attached-hosts/:hostname', handle((req) => getAttachedHost(req.params.hostname)));
  router.delete('/attached-hosts/:hostname', handle((req) => {
    const result = detachHost({ hostname: req.params.hostname });
    reloadRoutes();
    return result;
  }));
  router.post('/zones', handle((req) => createZone(req.body || {})));
  router.post('/invites', handle((req) => generateInvite(req.body || {})));
  router.get('/invites', handle(() => listInvites()));
  router.post('/invites/redeem', handle((req) => redeemInvite(req.body || {})));
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
