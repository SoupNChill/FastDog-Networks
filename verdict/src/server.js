import express from 'express';
import { dirname, join } from 'node:path';
import { createDecisionLog } from './metering/decisions.js';
import { edgeRouter } from './edge/routes.js';
import { createKeyStore } from './auth/keys.js';
import { createMeter } from './metering/usage.js';
import { v1Router } from './routes/v1.js';
import { openapi } from './openapi.js';
import { createRateLimiter } from './middleware/rateLimit.js';

export async function createApp({
  keyFile = process.env.VERDICT_KEY_FILE || 'data/keys.json',
  usageFile = process.env.VERDICT_USAGE_FILE || 'data/usage.json',
  decisionFile = process.env.VERDICT_DECISION_FILE || join(dirname(usageFile), 'decisions.jsonl'),
  clearanceSecret = process.env.VERDICT_CLEARANCE_SECRET,
  clearanceTTL = Number(process.env.VERDICT_CLEARANCE_TTL_SECONDS || 300),
  demoForce = process.env.VERDICT_DEMO_FORCE === '1',
  allowBootstrap = process.env.VERDICT_ALLOW_BOOTSTRAP === '1',
  ipRateLimit = createRateLimiter({ max: Number(process.env.VERDICT_IP_RATE_LIMIT_MAX || 120), keyBy: req => req.socket.remoteAddress, headerPrefix: 'X-IP-RateLimit' }),
  rateLimit,
} = {}) {
  const store = createKeyStore(keyFile);
  await store.load();
  const meter = createMeter({ file: usageFile });
  await meter.load();
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '256kb' }));
  const logDecision = createDecisionLog(decisionFile);
  app.use(edgeRouter({ secret: clearanceSecret, ttl: Number.isInteger(clearanceTTL) && clearanceTTL > 0 ? clearanceTTL : 300, demoForce, logDecision }));
  app.get('/health', (_req, res) => res.json({ ok: true, service: 'verdict', version: '0.2.0' }));
  app.get('/openapi.json', (_req, res) => res.json(openapi));
  app.use('/', express.static('public'));
  app.use('/v1', v1Router(store, meter, { rateLimit: rateLimit || createRateLimiter(), ipRateLimit, logDecision, allowBootstrap }));
  app.use((error, _req, res, _next) => {
    if (error.type === 'entity.too.large') return res.status(413).json({ error: 'payload_too_large' });
    if (error instanceof SyntaxError && 'body' in error) return res.status(400).json({ error: 'invalid_json' });
    if (error.status === 401) return res.status(401).json({ error: 'unauthorized' });
    console.error(error);
    res.status(500).json({ error: 'internal_error' });
  });
  return app;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  const port = Number(process.env.PORT || 8080);
  const app = await createApp();
  const bind = process.env.VERDICT_BIND || '127.0.0.1';
  app.listen(port, bind, () => console.log(`verdict listening on ${bind}:${port}`));
}
