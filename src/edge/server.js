/**
 * Fastdog Edge — Phase 1 reverse proxy + control/DNS API + WS tunnel hub.
 *
 * LAN local-prod only. Do NOT expose EDGE_PORT to the public internet.
 */
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { WebSocketServer } from 'ws';
import { env, loadRoutes, defaultUpstream, ROOT } from '../lib/config.js';
import { forwardHttp } from '../lib/http-forward.js';
import { inc, get as getMetrics } from '../lib/metrics.js';
import {
  closeHost,
  listAgents,
  registerAgent,
  attachWs,
  detachWs,
  getAgentByHost,
  proxyViaTunnel,
  parseMaxBodyBytes,
} from '../control/tunnels.js';
import { operatorAuth } from '../control/auth.js';
import { createInternalServer, assertLoopbackBind } from '../internal/server.js';
import { dataDir } from '../onboard/json.js';
import { watchTunnel } from '../control/heartbeat.js';
import { assertSafeStartup, DEFAULT_AGENT_TOKEN } from '../lib/startup-guard.js';
import { dnsRouter } from '../dns/api.js';
import { onboardRouter } from '../onboard/api.js';
import { statusService, intervalMs as statusIntervalMs } from '../status/service.js';
import { renderStatus } from '../status/html.js';
import { billingRouter, billingWebhook } from '../billing/api.js';
import { isNonCanonicalControlPath, isControlPath } from './control-path.js';
import { createOperatorServer, OPERATOR_BIND, OPERATOR_PORT } from '../operator/server.js';
import { createPausedHosts, servePaused, upgradeUrl } from './paused-hosts.js';

const PORT = Number(env('EDGE_PORT', '8787'));
const BIND = env('EDGE_BIND', '127.0.0.1');
assertSafeStartup();
const AGENT_TOKEN = process.env.AGENT_TOKEN?.trim() ? process.env.AGENT_TOKEN : DEFAULT_AGENT_TOKEN;
const MAX_BODY_BYTES = parseMaxBodyBytes(process.env.EDGE_MAX_BODY_BYTES);
const ALLOW_QUERY_TOKEN = env('ALLOW_QUERY_TOKEN', '1') !== '0';
// Successful legacy tunnel connections since this process started.
let queryTokenFallbackUses = 0;

let routeConfig = loadRoutes();
const pausedHosts = createPausedHosts({ dataDir: dataDir() });
const PAUSED_UPGRADE_URL = upgradeUrl(process.env.PAUSED_UPGRADE_URL);

function reloadRoutes() {
  routeConfig = loadRoutes();
  return {
    file: routeConfig.file,
    hosts: [...routeConfig.routes.keys()],
    tunnelHosts: [...routeConfig.tunnelHosts],
  };
}

function resolveUpstream(hostname) {
  const host = String(hostname || '').split(':')[0].toLowerCase();
  if (routeConfig.routes.has(host)) return { kind: 'static', upstream: routeConfig.routes.get(host) };
  const agent = getAgentByHost(host);
  if (agent) return { kind: 'tunnel', agent };
  if (routeConfig.tunnelHosts.has(host)) {
    const a = getAgentByHost(host);
    if (a) return { kind: 'tunnel', agent: a };
  }
  return { kind: 'default', upstream: defaultUpstream() };
}

const app = express();
app.disable('x-powered-by');
// The control namespace is only reachable by its exact raw spelling; never forward variants to a tenant.
function controlNotFound(res) {
  res.status(404).type('text/plain').send('Not Found\n');
}
app.use((req, res, next) => (isNonCanonicalControlPath(req.url) ? controlNotFound(res) : next()));
// Marketing preview only. Keep /www separate from the edge APIs and operator listener.
app.use('/www', express.static(fileURLToPath(new URL('../../site/', import.meta.url)), { index: 'index.html', fallthrough: false }));
// Never let the default error handler echo filesystem paths for missing marketing files.
app.use('/www', (err, req, res, next) => {
  if (res.headersSent) return next(err);
  const notFound = ['ENOENT', 'ENOTDIR', 'ENAMETOOLONG'].includes(err && err.code);
  const raw = notFound ? 404 : Number((err && (err.status || err.statusCode)) || 500);
  const code = raw >= 400 && raw < 600 ? raw : 500;
  if (code >= 500) console.error('www_static_error', (err && err.code) || code);
  const text = { 400: 'Bad Request', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed' }[code] || 'Error';
  if (err && err.headers && typeof err.headers === 'object') res.set(err.headers);
  res.set('X-Content-Type-Options', 'nosniff');
  res.status(code).type('html').send(`<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><title>${code} ${text}</title></head><body><h1>${code} ${text}</h1></body></html>\n`);
});
app.post('/_fastdog/billing/webhook', express.raw({ type: 'application/json', limit: '1mb' }), billingWebhook);
// JSON only for control/billing APIs — never the catch-all reverse proxy.
// A global express.json() consumes the body; proxyViaTunnel then waits forever on 'end'.
const jsonParser = express.json({ limit: '1mb' });
app.use('/_fastdog', jsonParser);
app.use(billingRouter());
const requireOperator = operatorAuth(AGENT_TOKEN);

const VERSION = '0.1.0';

function isLoopbackRequest(req) {
  if (req.headers['x-forwarded-for']) return false;
  const addr = req.socket?.remoteAddress || '';
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}

app.get('/health', (req, res) => {
  if (isLoopbackRequest(req)) {
    return res.json({
      ok: true,
      service: 'fastdog-edge',
      version: VERSION,
      phase: 1,
      listen: `${BIND}:${PORT}`,
      warning: 'LAN-only — do not expose to public internet',
      routesFile: routeConfig.file,
      routeCount: routeConfig.routes.size,
      agents: listAgents().length,
      queryTokenFallbackUses,
    });
  }
  res.json({ ok: true, version: VERSION });
});

app.get('/status', async (req, res) => {
  const status = await statusService.get({ force: req.query.refresh === '1' });
  res.type('html').send(renderStatus(status));
});

app.get('/status.json', async (req, res) => {
  res.json(await statusService.get({ force: req.query.refresh === '1' }));
});

app.get('/_fastdog/metrics', requireOperator, (_req, res) => {
  const agents = listAgents();
  res.json(getMetrics({
    agentsRegistered: agents.length,
    agentsConnected: agents.filter((agent) => agent.connected).length,
  }));
});

// --- Control API (agents) ---
app.get('/_fastdog/agents', requireOperator, (_req, res) => {
  res.json({ agents: listAgents() });
});

// A present Authorization header is authoritative, including malformed headers.
// Never log credentials, request URLs, or authentication error details here.
function agentToken(req, legacyToken) {
  if (req.headers.authorization !== undefined) {
    return /^Bearer ([^\s]+)$/i.exec(req.headers.authorization)?.[1] || '';
  }
  return legacyToken;
}

app.post('/_fastdog/agents/register', (req, res) => {
  try {
    const result = registerAgent({
      name: req.body?.name,
      hostname: req.body?.hostname,
      localUpstream: req.body?.localUpstream,
      token: agentToken(req, req.body?.token || req.headers['x-fastdog-token']),
      expectedToken: AGENT_TOKEN,
    });
    res.status(201).json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.post('/_fastdog/routes/reload', requireOperator, (_req, res) => {
  res.json(reloadRoutes());
});

app.get('/_fastdog/routes', requireOperator, (_req, res) => {
  res.json({
    file: routeConfig.file,
    routes: Object.fromEntries(routeConfig.routes),
    tunnelHosts: [...routeConfig.tunnelHosts],
    defaultUpstream: defaultUpstream(),
  });
});

// --- DNS control plane ---
app.use('/_fastdog/dns', requireOperator, dnsRouter());
app.use('/_fastdog/onboard', onboardRouter({ reloadRoutes, staticRouteForHost: (host) => routeConfig.routes.has(host) }));

// Catch-all reverse proxy (after control routes)
app.use((req, res) => {
  // Unmatched control routes (e.g. /_fastdog/unknown) are not tenant traffic either.
  if (isControlPath(req.url)) return controlNotFound(res);
  const host = req.headers.host || '';
  const resolved = resolveUpstream(host);
  // Trial pause is fail-open: any error here proxies as usual.
  try {
    const tunnelHost = routeConfig.tunnelHosts.has(String(host).split(':')[0].toLowerCase());
    if (servePaused(req, res, { resolved, tunnelHost, isPaused: pausedHosts.isPaused, link: PAUSED_UPGRADE_URL })) return;
  } catch { if (res.headersSent) return; }

  inc('requestsProxied');

  if (resolved.kind === 'tunnel') {
    inc('requestsTunnel');
    return proxyViaTunnel(resolved.agent, req, res, { maxBodyBytes: MAX_BODY_BYTES });
  }

  if (resolved.kind === 'static') inc('requestsStatic');

  forwardHttp(req, res, resolved.upstream, {
    extraHeaders: {
      'x-fastdog-edge': '1',
      'x-fastdog-route': resolved.kind,
    },
  });
});

const server = http.createServer(app);
const operatorServer = createOperatorServer({ edgeHealthy: () => server.listening });
const internalEnabled = env('INTERNAL_ENABLED', '0') === '1';
const internalBind = internalEnabled ? assertLoopbackBind(env('INTERNAL_BIND', '127.0.0.1')) : null;
const internalPort = Number(env('INTERNAL_PORT', '8789'));
if (internalEnabled && (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65535)) throw new Error('invalid INTERNAL_PORT');
const internalServer = internalEnabled ? createInternalServer({
  portalKey: env('PORTAL_KEY', ''), agentToken: AGENT_TOKEN, dataDir: dataDir(),
  registry: { getAgentByHost, closeHost }, recheckEnabled: env('RECHECK_ENABLED', '0') === '1',
  timeoutCodes: env('INTERNAL_TIMEOUT_CODES', '0') === '1', claimCreateRateLimit: env('CLAIM_CREATE_RATE_LIMIT', '0'),
}) : null;
internalServer?.on('routesChanged', reloadRoutes);
internalServer?.on('routesChanged', () => pausedHosts.invalidate());

const wss = new WebSocketServer({ server, path: '/_fastdog/tunnel' });

wss.on('connection', (ws, req) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const agentId = url.searchParams.get('agentId');
  // Deprecated: query tokens support 0.1.0 only; remove after migration to 0.1.1+.
  const queryToken = ALLOW_QUERY_TOKEN ? url.searchParams.get('token') : null;
  const token = agentToken(req, queryToken || req.headers['x-fastdog-token']);

  if (!agentId || !attachWs(agentId, ws, token)) {
    ws.close(4401, 'unauthorized');
    return;
  }

  if (req.headers.authorization === undefined && queryToken) queryTokenFallbackUses++;

  ws.send(JSON.stringify({ type: 'welcome', agentId, protocol: 'fastdog-tunnel-v0' }));

  watchTunnel(ws, agentId);
  ws.on('close', () => detachWs(agentId, ws));
  ws.on('error', () => detachWs(agentId, ws));
});

if (process.env.NODE_ENV !== 'test') {
  if (OPERATOR_BIND !== '127.0.0.1' && OPERATOR_BIND !== '::1') throw new Error('OPERATOR_BIND must be a loopback address');
  if (!Number.isSafeInteger(OPERATOR_PORT) || OPERATOR_PORT < 1 || OPERATOR_PORT > 65535) throw new Error('invalid OPERATOR_PORT');
  if (OPERATOR_PORT === PORT && OPERATOR_BIND === BIND) throw new Error('operator and edge listeners conflict');
  if (statusIntervalMs > 0) setInterval(() => {
    statusService.refresh().catch((error) => console.warn(`status: periodic check failed: ${error.message}`));
  }, statusIntervalMs).unref();
  internalServer?.listen(internalPort, internalBind);
  server.listen(PORT, BIND, () => {
    console.log(`fastdog-edge listening on http://${BIND}:${PORT}`);
    console.log(`  health:  GET /health`);
    console.log(`  status:  http://${BIND}:${PORT}/status`);
    console.log(`  control: /_fastdog/*  dns: /_fastdog/dns/*  ws: /_fastdog/tunnel`);
    console.log(`  billing: GET /pricing  /_fastdog/billing/* (TEST MODE)`);
    console.log(`  routes:  ${routeConfig.file}`);
    console.log(`  root:    ${ROOT}`);
    console.log('  WARNING: LAN-only — do not expose to public internet');
  });
  operatorServer.listen(OPERATOR_PORT, OPERATOR_BIND, () => {
    console.log(`fastdog operator listening on http://${OPERATOR_BIND}:${OPERATOR_PORT}/ (loopback only)`);
  });
}

export { app, server, operatorServer, internalServer, resolveUpstream, reloadRoutes, PORT, BIND };
