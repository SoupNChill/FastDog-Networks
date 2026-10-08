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
  headers: z.record(z.string().max(2048)).optional(),
  account_age_hours: z.number().nonnegative().optional(),
  prior_score: z.number().min(0).max(1).optional(),
  signals: z.array(z.string().max(512)).max(100).optional(),
  notes: z.string().max(8192).optional(),
}).passthrough();

const Body = z.union([
  State,
  z.object({ state: z.union([State, z.string().max(16384)]) }),
]);

export function v1Router(store, meter, { rateLimit } = {}) {
  const router = Router();
  const limiter = rateLimit || createRateLimiter();
  router.use(keyAuth(store));

  router.post('/keys', async (req, res, next) => {
    const parsed = z.object({ name: z.string().min(1).max(80).default('default') }).safeParse(req.body ?? {});
    if (!parsed.success) return res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
    try {
      res.status(201).json(await store.create(parsed.data.name, { bootstrapOnly: !req.apiKey }));
    } catch (error) {
      next(error);
    }
  });

  router.get('/usage', (req, res) => {
    res.json({ key_id: req.apiKey.id, ...meter.get(req.apiKey.id), period: 'persistent' });
  });

  router.post('/decide', limiter, async (req, res, next) => {
    if (req.body == null || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({ error: 'invalid_body', details: { formErrors: ['body must be a JSON object'], fieldErrors: {} } });
    }
    const parsed = Body.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
    }
    const state = 'state' in parsed.data ? parsed.data.state : parsed.data;
    try {
      const decision = await decide(state);
      if (req.apiKey) await meter.record(req.apiKey.id, decision.engine);
      res.json({ ...decision, request_id: randomUUID() });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
