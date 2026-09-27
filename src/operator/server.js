import http from 'node:http';
import express from 'express';
import { env } from '../lib/config.js';
import { listZones, readZone } from '../dns/store.js';
import { createZone, nsInstructions, domain } from '../onboard/store.js';
import { listInvites, generateInvite } from '../onboard/invites.js';
import { listAccounts } from '../billing/store.js';
import { listAgents } from '../control/tunnels.js';
import { statusService } from '../status/service.js';
import { renderStatus } from '../status/html.js';
import { summarizeOperatorMetrics } from './metrics.js';
import { renderOperator } from './html.js';
import { runChecklist } from './checklist.js';
import { readFileSync } from 'node:fs';

export const OPERATOR_PORT = Number(env('OPERATOR_PORT', '8788'));
export const OPERATOR_BIND = env('OPERATOR_BIND', '127.0.0.1');

export function createOperatorApp({ edgeHealthy = () => false, checklist = runChecklist } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));
  app.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'self'");
    next();
  });
  app.get('/', (_req, res) => res.type('html').send(renderOperator()));
  app.get('/operator.js', (_req, res) => res.type('javascript').send(readFileSync(new URL('./client.js', import.meta.url), 'utf8')));
  app.use((req, res, next) => {
    if (req.headers['x-fastdog-token'] !== env('AGENT_TOKEN', 'fastdog-local-dev-token')) return res.status(401).json({ error: 'unauthorized' });
    next();
  });
  app.get('/_fastdog/operator/metrics', (_req, res) => {
    try {
      res.json(summarizeOperatorMetrics({ zones: listZones(), invites: listInvites(), accounts: listAccounts(), agents: listAgents(), edgeHealthOk: edgeHealthy() }));
    } catch (error) { res.status(500).json({ error: error.message }); }
  });
  app.get('/_fastdog/dns/zones', (_req, res) => res.json({ zones: listZones() }));
  app.get('/_fastdog/dns/zones/:zone', (req, res) => {
    try {
      const zone = readZone(domain(req.params.zone));
      if (!zone) return res.status(404).json({ error: 'zone_not_found' });
      res.json(zone);
    } catch (error) { res.status(error.status || 500).json({ error: error.message }); }
  });
  app.post('/_fastdog/onboard/zones', (req, res) => {
    try {
      const created = createZone(req.body || {});
      res.status(201).json({ ...created, instructions: nsInstructions(created.zone), hold: 'Registrar NS is on HOLD. Do not flip nameservers.' });
    } catch (error) { res.status(error.status || 500).json({ error: error.message }); }
  });
  app.get('/_fastdog/onboard/zones/:zone/ns-instructions', (req, res) => {
    try { res.json(nsInstructions(req.params.zone)); }
    catch (error) { res.status(error.status || 500).json({ error: error.message }); }
  });
  app.get('/_fastdog/operator/ns-cut-checklist', async (_req, res) => {
    try { res.json(await checklist()); }
    catch (error) { res.json({ SAFE_TO_FLIP: 'no', checks: [], lines: [], hold: 'Registrar NS is on HOLD. This tool never flips nameservers.', error: error.message }); }
  });
  app.get('/_fastdog/agents', (_req, res) => res.json({ agents: listAgents() }));
  app.get('/_fastdog/onboard/invites', (_req, res) => res.json(listInvites().map(({ code, ...invite }) => invite)));
  app.post('/_fastdog/onboard/invites', (req, res) => {
    try { res.status(201).json(generateInvite(req.body || {})); }
    catch (error) { res.status(error.status || 500).json({ error: error.message }); }
  });
  app.get('/status.json', async (_req, res) => res.json(await statusService.get()));
  app.get('/status', async (_req, res) => res.type('html').send(renderStatus(await statusService.get())));
  return app;
}

export function createOperatorServer(options) {
  return http.createServer(createOperatorApp(options));
}
