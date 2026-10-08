import { demoPage } from './edge/demo.js';
import express from 'express';
import { readFileSync } from 'node:fs';
import { createMetrics } from './metering/metrics.js';
import { dirname, join } from 'node:path';
import { createDecisionLog } from './metering/decisions.js';
import { edgeRouter } from './edge/routes.js';
import { createKeyStore } from './auth/keys.js';
import { createMeter } from './metering/usage.js';
import { v1Router } from './routes/v1.js';
import { openapi } from './openapi.js';
import { createRateLimiter, ipBucketKey } from './middleware/rateLimit.js';
import { createHostStore } from './config/hosts.js';
import { asnDb } from './asn/lookup.js';
import { clientIP } from './edge/security.js';

const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

export async function createApp({
  keyFile = process.env.VERDICT_KEY_FILE || 'data/keys.json',
  usageFile = process.env.VERDICT_USAGE_FILE || 'data/usage.json',
  decisionFile = process.env.VERDICT_DECISION_FILE || join(dirname(usageFile), 'decisions.jsonl'),
  hostsFile = process.env.VERDICT_HOSTS_FILE || join(dirname(usageFile), 'hosts.json'),
  shadowFile = process.env.VERDICT_SHADOW_FILE || join(dirname(usageFile), 'shadow.jsonl'),
  asnFile = process.env.VERDICT_ASN_FILE,
  clearanceSecret = process.env.VERDICT_CLEARANCE_SECRET,
  clearanceTTL = Number(process.env.VERDICT_CLEARANCE_TTL_SECONDS || 300),
  edgeGoodBotDNS = process.env.VERDICT_EDGE_GOODBOT_DNS === '1',
  decisionWriter,
  demoForce = process.env.VERDICT_DEMO_FORCE === '1',
  allowBootstrap = process.env.VERDICT_ALLOW_BOOTSTRAP === '1',
  ipRateLimit,
  rateLimit,
  hostStore: hostStoreOpt,
} = {}) {
  const store = createKeyStore(keyFile);
  await store.load();
  const meter = createMeter({ file: usageFile });
  await meter.load();
  const hostStore = hostStoreOpt || createHostStore(hostsFile);
  await hostStore.load();
  if (asnFile) {
    try { await asnDb.loadFile(asnFile); console.log(`asn db rows=${asnDb.rows}`); }
    catch (e) { console.warn('asn load skipped:', e.message); }
  }
  const app = express();
  app.disable('x-powered-by');
  const metrics = createMetrics();
  app.use(metrics.middleware);
  app.get('/metrics', (_req, res) => res.set('Cache-Control', 'no-store').json(metrics.snapshot()));
  app.use(express.json({ limit: '256kb' }));
  const appendDecision = decisionWriter || createDecisionLog(decisionFile);
  const logDecision = record => {
    metrics.decision(record.action);
    Promise.resolve().then(() => appendDecision(record)).catch(error => console.error('decision log failed:', error.message));
  };
  app.locals.flush = async () => {
    await Promise.resolve();
    await Promise.all([meter.ready(), appendDecision.ready?.(), hostStore.ready?.()]);
  };
  app.locals.hostStore = hostStore;
  app.locals.metrics = metrics;
  const ipLimiter = ipRateLimit || createRateLimiter({
    max: Number(process.env.VERDICT_IP_RATE_LIMIT_MAX || 120),
    keyBy: req => ipBucketKey(clientIP(req)),
    headerPrefix: 'X-IP-RateLimit',
  });
  app.use(edgeRouter({ secret: clearanceSecret, ttl: Number.isInteger(clearanceTTL) && clearanceTTL > 0 ? clearanceTTL : 300, demoForce, edgeGoodBotDNS, logDecision }));
  app.get('/demo', (_req, res) => res.set('Cache-Control', 'no-store').type('html').send(demoPage(demoForce)));
  app.get('/health', (_req, res) => res.json({ ok: true, service: 'verdict', version }));
  app.get('/openapi.json', (_req, res) => res.json(openapi));
  app.use('/', express.static('public'));
  app.use('/v1', v1Router(store, meter, {
    rateLimit: rateLimit || createRateLimiter(),
    ipRateLimit: ipLimiter,
    logDecision,
    allowBootstrap,
    hostStore,
    shadowFile,
    metrics,
  }));
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
  const server = app.listen(port, bind, () => console.log(`verdict listening on ${bind}:${port}`));
  const shutdown = () => server.close(async () => { await app.locals.flush(); });
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}
