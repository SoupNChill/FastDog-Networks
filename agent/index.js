/**
 * Fastdog tunnel agent (v0 stub).
 *
 * Outbound connector: registers with edge control API, opens WebSocket,
 * receives HTTP-over-WS frames, fetches AGENT_LOCAL_UPSTREAM, returns response.
 *
 * Enough shape to eventually replace cloudflared for Summit Lease dogfood.
 * TODO: multiplex streams, binary frames, TLS to edge,
 *       multi-host, CONNECT/WebSocket upgrade passthrough.
 */
import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';
import { pathToFileURL } from 'node:url';
import WebSocket from 'ws';
import { computeBackoffMs } from './backoff.js';
import { startHeartbeat } from './heartbeat.js';

function env(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

const EDGE_HTTP = env('EDGE_HTTP_URL', 'http://127.0.0.1:8787');
const EDGE_WS = env('EDGE_WS_URL', 'ws://127.0.0.1:8787/_fastdog/tunnel');
const TOKEN = env('AGENT_TOKEN', '');
const NAME = env('AGENT_NAME', '');
const HOSTNAME = env('AGENT_HOSTNAME', '');
const LOCAL_UPSTREAM = env('AGENT_LOCAL_UPSTREAM', 'http://127.0.0.1:9999').replace(/\/$/, '');

export async function register() {
  const res = await fetch(`${EDGE_HTTP.replace(/\/$/, '')}/_fastdog/agents/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', Authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify({
      name: NAME,
      hostname: HOSTNAME,
      localUpstream: LOCAL_UPSTREAM,
    }),
  });
  if (!res.ok) throw new Error(`register failed: ${res.status}`);
  return res.json();
}

function fetchLocal(method, path, headers, bodyBuf) {
  return new Promise((resolve, reject) => {
    const target = new URL(path || '/', LOCAL_UPSTREAM);
    const isHttps = target.protocol === 'https:';
    const lib = isHttps ? https : http;
    // Preserve client Host from the edge (Host-based apps); only use LOCAL_UPSTREAM for TCP.
    const hdrs = { ...headers };
    delete hdrs['transfer-encoding'];
    delete hdrs.connection;
    delete hdrs['content-length'];
    if (!hdrs.host && !hdrs.Host) hdrs.host = target.host;

    const req = lib.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (isHttps ? 443 : 80),
        path: target.pathname + target.search,
        method,
        headers: hdrs,
        timeout: 25000,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            status: res.statusCode || 502,
            headers: res.headers,
            body: Buffer.concat(chunks),
          });
        });
      },
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('local upstream timeout')));
    if (bodyBuf?.length) req.write(bodyBuf);
    req.end();
  });
}

// Any HTTP response means the app is listening; only reachability is reported, never response content.
export function probeOrigin(upstream = LOCAL_UPSTREAM, { timeoutMs = 3000 } = {}) {
  return new Promise((resolve) => {
    let url;
    try { url = new URL(`${upstream}/`); } catch { resolve(false); return; }
    const client = url.protocol === 'https:' ? https : http;
    const req = client.request(url, { method: 'HEAD', timeout: timeoutMs, rejectUnauthorized: false }, (res) => { res.resume(); resolve(true); });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
    req.end();
  });
}
let originStatus = {};
async function refreshOrigin() {
  originStatus = { origin_reachable: await probeOrigin(), origin_checked_at: new Date().toISOString() };
}
export const currentOriginStatus = () => originStatus;

async function handleFrame(ws, msg) {
  if (msg.type !== 'http_req') return;
  try {
    const bodyBuf = msg.bodyBase64 ? Buffer.from(msg.bodyBase64, 'base64') : null;
    const result = await fetchLocal(msg.method, msg.path, msg.headers || {}, bodyBuf);
    const outHeaders = { ...result.headers };
    delete outHeaders['transfer-encoding'];
    delete outHeaders['content-length'];
    ws.send(
      JSON.stringify({
        type: 'http_res',
        id: msg.id,
        status: result.status,
        headers: outHeaders,
        bodyBase64: result.body.length ? result.body.toString('base64') : undefined,
      }),
    );
  } catch (err) {
    ws.send(
      JSON.stringify({
        type: 'http_res',
        id: msg.id,
        status: 502,
        headers: { 'content-type': 'application/json' },
        bodyBase64: Buffer.from(JSON.stringify({ error: 'agent_upstream_failed', detail: err.message })).toString('base64'),
      }),
    );
  }
}

let activeSocket;

export function connectWs(agentId, onWelcome) {
  const u = new URL(EDGE_WS);
  u.searchParams.set('agentId', agentId);
  u.searchParams.delete('token');

  return new Promise((resolve) => {
    const ws = new WebSocket(u.toString(), { headers: { Authorization: `Bearer ${TOKEN}` } });
    activeSocket = ws;
    ws.on('open', () => {
      console.log('[agent] tunnel connected');
      refreshOrigin();
      const probe = setInterval(refreshOrigin, 20000);
      probe.unref?.();
      ws.once('close', () => clearInterval(probe));
      startHeartbeat(ws, { status: currentOriginStatus });
    });
    ws.on('message', (data) => {
      let msg;
      try {
        msg = JSON.parse(String(data));
      } catch {
        return;
      }
      if (msg.type === 'welcome') {
        console.log('[agent] tunnel ready');
        onWelcome();
        return;
      }
      if (msg.type === 'pong') return;
      handleFrame(ws, msg);
    });
    ws.on('close', (code) => {
      if (activeSocket === ws) activeSocket = undefined;
      console.warn(`[agent] ws closed ${code}`);
      resolve();
    });
    ws.on('error', () => console.error('[agent] connection error'));
  });
}

export async function reconnectLoop({ registerAgent = register, connect = connectWs, delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), backoff = computeBackoffMs } = {}) {
  let attempt = 0;
  for (;;) {
    try {
      console.log('[agent] registering');
      const reg = await registerAgent();
      console.log('[agent] registered');
      await connect(reg.id, () => { attempt = 0; });
    } catch (err) {
      console.error('[agent] registration or connection failed. Check the connection settings.');
    }
    const nextDelay = backoff(attempt);
    console.warn(`[agent] reconnect attempt ${attempt + 1}, next delay ${nextDelay}ms`);
    attempt += 1;
    await delay(nextDelay);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href && process.env.FASTDOG_AGENT_NO_MAIN !== '1') {
  if (!TOKEN.trim()) {
    console.error('[agent] AGENT_TOKEN is required. Set the connection token before starting.');
    process.exit(1);
  }
  const stop = () => {
    if (activeSocket) {
      try { activeSocket.close(1000, 'shutdown'); } catch { /* Already closed. */ }
      setTimeout(() => {
        activeSocket?.terminate();
        process.exit(0);
      }, 100).unref();
      activeSocket.once('close', () => process.exit(0));
    } else {
      process.exit(0);
    }
  };
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
  reconnectLoop();
}
