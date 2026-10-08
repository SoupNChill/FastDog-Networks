import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { keyAuth } from '../auth/keys.js';
import { decide } from '../engine/jev.js';
import { createRateLimiter } from '../middleware/rateLimit.js';

const State = z.object({
  ip: z.string().max(64).optional(),
  asn: z.union([z.string(), z.number()]).optional(),
  ja3: z.string().max(256).optional(),
  path: z.string().max(2048).optional(),
  method: z.string().max(32).optional(),
  ua: z.string().max(2048).optional(),
  headers: z.object({ _order: z.array(z.string().max(256)).max(100).optional(), header_order: z.array(z.string().max(256)).max(100).optional() }).catchall(z.string().max(2048)).optional(),
  header_order: z.array(z.string().max(256)).max(100).optional(),
  account_age_hours: z.number().nonnegative().optional(),
  prior_score: z.number().min(0).max(1).optional(),
  signals: z.array(z.string().max(512)).max(100).optional(),
  notes: z.string().max(8192).optional(),
}).passthrough();

const WrappedBody = z.object({ state: z.union([State, z.string().max(16384)]) });

export function v1Router(store, meter, { rateLimit, ipRateLimit, logDecision, allowBootstrap, hostStore, shadowFile, metrics } = {}) {
  const router = Router();
  const limiter = rateLimit || createRateLimiter();
  router.use(keyAuth(store, { allowBootstrap }));

  router.post('/keys', async (req, res, next) => {
    const parsed = z.object({ name: z.string().min(1).max(80).default('default') }).safeParse(req.body ?? {});
    if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
    try {
      res.status(201).json(await store.create(parsed.data.name, { bootstrapOnly: !req.apiKey }));
    } catch (error) {
      next(error);
    }
  });

  router.post('/keys/:id/revoke', async (req, res, next) => {
    try {
      if (!await store.revoke(req.params.id)) return res.status(404).json({ error: 'key_not_found' });
      res.json({ ok: true });
    } catch (error) { next(error); }
  });

  router.get('/usage', (req, res) => {
    res.json({ key_id: req.apiKey.id, ...meter.get(req.apiKey.id), period: 'persistent' });
  });

  router.post('/decide', ipRateLimit, limiter, async (req, res, next) => {
    if (req.body == null || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({ error: 'invalid_body', details: { formErrors: ['body must be a JSON object'], fieldErrors: {} } });
    }
    const parsed = ('state' in req.body ? WrappedBody : State).safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
    }
    const state = 'state' in parsed.data ? parsed.data.state : parsed.data;
    try {
      const decision = await decide(state);
      if (req.apiKey) meter.record(req.apiKey.id, decision.engine);
      const request_id = randomUUID();
      logDecision({ ...decision, request_id, ip: req.socket.remoteAddress, path: state?.path, key_id: req.apiKey.id });
      res.json({ ...decision, request_id });
    } catch (error) {
      next(error);
    }
  });


  // --- per-host config ---
  if (hostStore) {
    router.get('/hosts', (_req, res) => res.json({ hosts: hostStore.list() }));
    router.get('/hosts/:host', (req, res) => {
      const row = hostStore.get(req.params.host);
      if (!row) return res.status(404).json({ error: 'host_not_found' });
      res.json(row);
    });
    router.put('/hosts/:host', async (req, res, next) => {
      try {
        const row = await hostStore.set(req.params.host, req.body || {});
        res.json(row);
      } catch (error) {
        if (error.status) return res.status(error.status).json({ error: error.message, detail: error.detail });
        next(error);
      }
    });
    router.delete('/hosts/:host', async (req, res, next) => {
      try {
        if (!await hostStore.remove(req.params.host)) return res.status(404).json({ error: 'host_not_found' });
        res.json({ ok: true });
      } catch (error) { next(error); }
    });
  }

  // --- read-only ops ---
  router.get('/ops/metrics', (_req, res) => {
    if (!metrics) return res.status(503).json({ error: 'metrics_unavailable' });
    res.json(metrics.snapshot());
  });
  router.get('/ops/shadow-summary', async (_req, res, next) => {
    try {
      const { buildShadowSummary } = await import('../shadow/summary.js');
      const file = shadowFile || process.env.VERDICT_SHADOW_FILE || 'data/shadow.jsonl';
      res.json(await buildShadowSummary(file));
    } catch (error) { next(error); }
  });
  router.get('/ops/recent-decisions', async (req, res, next) => {
    try {
      const { createReadStream } = await import('node:fs');
      const { createInterface } = await import('node:readline');
      const file = process.env.VERDICT_DECISION_FILE || 'data/decisions.jsonl';
      const want = new Set(['challenge', 'block']);
      const rows = [];
      try {
        const rl = createInterface({ input: createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
        for await (const line of rl) {
          if (!line.trim()) continue;
          let row; try { row = JSON.parse(line); } catch { continue; }
          if (!want.has(row.action)) continue;
          rows.push({ ts: row.ts, action: row.action, reason: row.reason, path: row.path, engine: row.engine });
        }
      } catch (e) { if (e.code !== 'ENOENT') throw e; }
      res.json({ recent: rows.slice(-50).reverse() });
    } catch (error) { next(error); }
  });

  return router;
}

