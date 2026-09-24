import { env } from '../lib/config.js';
import { probeEdge, probeDns } from './probes.js';
import { readStatus, writeStatus } from './store.js';
import { createStatusService } from './aggregator.js';

function positiveNumber(name, fallback, allowZero = false) {
  const value = Number(env(name, String(fallback)));
  return Number.isFinite(value) && (value > 0 || (allowZero && value === 0)) ? value : fallback;
}

const timeoutMs = positiveNumber('STATUS_PROBE_TIMEOUT_MS', 3000);
export const intervalMs = positiveNumber('STATUS_INTERVAL_MS', 60000, true);
const edgeUrl = env('STATUS_EDGE_URL', 'https://edge.fastdognetworks.com/health');
const zone = env('STATUS_ZONE', 'fastdognetworks.com');
const ns1 = env('NS1_IP', '157.230.57.32');
const ns2 = env('NS2_IP', '2.29.58.90');
const webhook = env('STATUS_ALERT_WEBHOOK_URL', '');

async function alert(check, status) {
  console.warn(`status: ${check.name} turned red: ${check.detail}`);
  if (!webhook) return;
  const response = await fetch(webhook, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ service: check.id, check, overall: status.overall, lastChecked: status.lastChecked }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`webhook HTTP ${response.status}`);
}

export const statusService = createStatusService({
  probes: {
    edge: () => probeEdge(edgeUrl, timeoutMs),
    ns1: () => probeDns(ns1, zone, timeoutMs),
    ns2: () => probeDns(ns2, zone, timeoutMs),
  },
  read: readStatus,
  write: writeStatus,
  alert,
  intervalMs,
});
