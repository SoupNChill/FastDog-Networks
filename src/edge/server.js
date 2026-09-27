/**
 * Fastdog Edge — Phase 1 reverse proxy + control/DNS API + WS tunnel hub.
 *
 * LAN local-prod only. Do NOT expose EDGE_PORT to the public internet.
 * Summit Lease / Cloudflare on prod1 is untouched; this runs in parallel.
 */
import http from 'node:http';
import express from 'express';
import { WebSocketServer } from 'ws';
import { env, loadRoutes, defaultUpstream, ROOT } from '../lib/config.js';
import { forwardHttp } from '../lib/http-forward.js';
import { inc, get as getMetrics } from '../lib/metrics.js';
import {
  listAgents,
  registerAgent,
  attachWs,
  detachWs,
  getAgentByHost,
  proxyViaTunnel,
  touch,
} from '../control/tunnels.js';
import { dnsRouter } from '../dns/api.js';
import { onboardRouter } from '../onboard/api.js';
import { statusService, intervalMs as statusIntervalMs } from '../status/service.js';
import { renderStatus } from '../status/html.js';
import { billingRouter, billingWebhook } from '../billing/api.js';
import { createOperatorServer, OPERATOR_BIND, OPERATOR_PORT } from '../operator/server.js';

const PORT = Number(env('EDGE_PORT', '8787'));
const BIND = env('EDGE_BIND', '0.0.0.0');
const AGENT_TOKEN = env('AGENT_TOKEN', 'fastdog-local-dev-token');

let routeConfig = loadRoutes();

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
app.post('/_fastdog/billing/webhook', express.raw({ type: 'application/json', limit: '1mb' }), billingWebhook);
app.use(express.json({ limit: '1mb' }));
app.use(billingRouter());

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'fastdog-edge',
    version: '0.1.0',
    phase: 1,
    listen: `${BIND}:${PORT}`,
    warning: 'LAN-only — do not expose to public internet',
    routesFile: routeConfig.file,
    routeCount: routeConfig.routes.size,
    agents: listAgents().length,
  });
});

app.get('/status', async (req, res) => {
  const status = await statusService.get({ force: req.query.refresh === '1' });
  res.type('html').send(renderStatus(status));
});

app.get('/status.json', async (req, res) => {
  res.json(await statusService.get({ force: req.query.refresh === '1' }));
});

app.get('/_fastdog/metrics', (_req, res) => {
  const agents = listAgents();
  res.json(getMetrics({
    agentsRegistered: agents.length,
    agentsConnected: agents.filter((agent) => agent.connected).length,
  }));
});

// --- Control API (agents) ---
app.get('/_fastdog/agents', (_req, res) => {
  res.json({ agents: listAgents() });
});

app.post('/_fastdog/agents/register', (req, res) => {
  try {
    const result = registerAgent({
      name: req.body?.name,
      hostname: req.body?.hostname,
      localUpstream: req.body?.localUpstream,
      token: req.body?.token || req.headers['x-fastdog-token'],
      expectedToken: AGENT_TOKEN,
    });
    res.status(201).json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.post('/_fastdog/routes/reload', (_req, res) => {
  res.json(reloadRoutes());
});

app.get('/_fastdog/routes', (_req, res) => {
  res.json({
    file: routeConfig.file,
    routes: Object.fromEntries(routeConfig.routes),
    tunnelHosts: [...routeConfig.tunnelHosts],
    defaultUpstream: defaultUpstream(),
  });
});

// --- DNS control plane ---
app.use('/_fastdog/dns', dnsRouter());
app.use('/_fastdog/onboard', onboardRouter({ reloadRoutes, staticRouteForHost: (host) => routeConfig.routes.has(host) }));

// Catch-all reverse proxy (after control routes)
app.use((req, res) => {
  const host = req.headers.host || '';
  const resolved = resolveUpstream(host);

  inc('requestsProxied');

  if (resolved.kind === 'tunnel') {
    inc('requestsTunnel');
    return proxyViaTunnel(resolved.agent, req, res);
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

const wss = new WebSocketServer({ server, path: '/_fastdog/tunnel' });

wss.on('connection', (ws, req) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const agentId = url.searchParams.get('agentId');
  const token = url.searchParams.get('token') || req.headers['x-fastdog-token'];

  if (!agentId || !attachWs(agentId, ws, token)) {
    ws.close(4401, 'unauthorized');
    return;
  }

  ws.send(JSON.stringify({ type: 'welcome', agentId, protocol: 'fastdog-tunnel-v0' }));

  ws.on('message', () => touch(agentId));
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

export { app, server, operatorServer, resolveUpstream, reloadRoutes, PORT, BIND };
