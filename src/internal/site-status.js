// Per-website live status for the tenant portal. Every function here takes a hostname that the
// caller has already confirmed is an active claim of the requesting tenant. Network probes only
// ever connect to the local Caddy listener (never to an address derived from the hostname), so a
// tenant cannot point the edge at an arbitrary target.
import { open, stat } from 'node:fs/promises';
import { join } from 'node:path';
import tls from 'node:tls';
import https from 'node:https';

const HOUR = 3600000;
const DAY = 24 * HOUR;
const TAIL_BYTES = 16 * 1024 * 1024;
const HOST_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export function safeHost(host) {
  if (typeof host !== 'string' || !HOST_RE.test(host)) throw new Error('invalid hostname');
  return host;
}

// Read at most the last TAIL_BYTES of a file; null when it is missing or unreadable.
async function tailLines(file) {
  let handle;
  try {
    const { size } = await stat(file);
    handle = await open(file, 'r');
    const start = Math.max(0, size - TAIL_BYTES);
    const buffer = Buffer.alloc(size - start);
    await handle.read(buffer, 0, buffer.length, start);
    const lines = buffer.toString('utf8').split('\n');
    if (start > 0) lines.shift();
    return lines;
  } catch { return null; }
  finally { await handle?.close().catch(() => {}); }
}

const median = (values) => {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
};

// Requests over the last 24h from the per-host Caddy access log (one file per host, see
// deploy/caddy/access-logs.snippet). Hourly buckets, oldest first; p50 latency in milliseconds.
export async function trafficStats(host, { logDir, now = Date.now } = {}) {
  safeHost(host);
  if (!logDir) return { available: false };
  const lines = await tailLines(join(logDir, `${host}.log`));
  if (!lines) return { available: false };
  const end = now();
  const hourly = new Array(24).fill(0);
  const durations = [];
  let errors = 0;
  for (const line of lines) {
    if (!line) continue;
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }
    const ts = typeof entry.ts === 'number' ? entry.ts * 1000 : Date.parse(entry.ts);
    if (!Number.isFinite(ts) || ts > end || ts <= end - DAY) continue;
    hourly[Math.min(23, 23 - Math.floor((end - ts) / HOUR))]++;
    if (typeof entry.duration === 'number' && entry.duration >= 0) durations.push(entry.duration * 1000);
    if (Number(entry.status) >= 500) errors++;
  }
  const p50 = median(durations);
  return { available: true, total: hourly.reduce((a, b) => a + b, 0), hourly,
    p50_ms: p50 === null ? null : Math.round(p50 * 10) / 10, errors_5xx: errors };
}

// Verdict shadow decisions for this host over 24h. Shadow only: nothing was actually blocked.
export async function shadowStats(host, { shadowFile, now = Date.now } = {}) {
  safeHost(host);
  if (!shadowFile) return { available: false, shadow: true };
  const lines = await tailLines(shadowFile);
  if (!lines) return { available: false, shadow: true };
  const end = now();
  let scored = 0; let blocked = 0; let challenged = 0;
  for (const line of lines) {
    if (!line || !line.includes(host)) continue;
    let entry;
    try { entry = JSON.parse(line); } catch { continue; }
    if (entry.host !== host) continue;
    const ts = Date.parse(entry.ts);
    if (!Number.isFinite(ts) || ts > end || ts <= end - DAY) continue;
    scored++;
    if (entry.action === 'block') blocked++;
    else if (entry.action === 'challenge') challenged++;
  }
  return { available: true, shadow: true, scored, would_block: blocked, would_challenge: challenged };
}

function certSummary(cert, authorized) {
  if (!cert || !cert.valid_to) return null;
  const expires = Date.parse(cert.valid_to);
  return { valid: Boolean(authorized), expires_at: Number.isFinite(expires) ? new Date(expires).toISOString() : null,
    issuer: typeof cert.issuer?.O === 'string' ? cert.issuer.O.slice(0, 80) : null };
}

// Certificate Caddy serves for this host, read over a loopback TLS handshake.
export function certInfo(host, { tlsHost = '127.0.0.1', tlsPort = 443, timeout = 4000 } = {}) {
  safeHost(host);
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => { if (!done) { done = true; socket.destroy(); resolve(value); } };
    const socket = tls.connect({ host: tlsHost, port: tlsPort, servername: host, rejectUnauthorized: false, timeout }, () => {
      finish(certSummary(socket.getPeerCertificate(), socket.authorized));
    });
    socket.on('timeout', () => finish(null));
    socket.on('error', () => finish(null));
  });
}

// "Test it": one GET / for the host through the local Caddy listener, exactly the path a visitor
// takes (Caddy -> edge -> tunnel -> origin). No redirects are followed and the body is discarded.
export function testSite(host, { tlsHost = '127.0.0.1', tlsPort = 443, timeout = 8000, now = () => performance.now() } = {}) {
  safeHost(host);
  return new Promise((resolve) => {
    const started = now();
    let done = false;
    const finish = (value) => { if (!done) { done = true; resolve({ ...value, ms: Math.round(now() - started) }); } };
    const req = https.request({ host: tlsHost, port: tlsPort, servername: host, method: 'GET', path: '/',
      headers: { host, 'user-agent': 'FastDog-Status-Test/1', accept: '*/*' }, rejectUnauthorized: false, agent: false, timeout }, (res) => {
      const cert = certSummary(res.socket.getPeerCertificate?.(), res.socket.authorized);
      const status = res.statusCode;
      res.destroy();
      finish({ ok: status < 500, status, cert });
    });
    req.on('timeout', () => { req.destroy(); finish({ ok: false, status: null, error: 'timeout', cert: null }); });
    req.on('error', () => finish({ ok: false, status: null, error: 'unreachable', cert: null }));
    req.end();
  });
}

// Live means: verified, an agent is connected, its origin check has not failed, and a valid
// certificate is being served. Older agents (before 0.1.1) report no origin check: unknown, not down.
export function liveState({ agent, cert, now = Date.now }) {
  const reasons = [];
  if (!agent?.connected) reasons.push('agent_disconnected');
  if (agent?.origin_reachable === false) reasons.push('origin_unreachable');
  if (!cert) reasons.push('certificate_missing');
  else if (!cert.valid) reasons.push('certificate_invalid');
  else if (cert.expires_at && Date.parse(cert.expires_at) <= now()) reasons.push('certificate_expired');
  return { live: reasons.length === 0, reasons };
}
