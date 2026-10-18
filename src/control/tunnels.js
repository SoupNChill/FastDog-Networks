import { combined, dataDir } from '../onboard/json.js';
import { validAgentVersion } from './agent-version.js';
import { randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { inc } from '../lib/metrics.js';
import { validCredential, tenantOwner } from '../onboard/credentials.js';
import { normalizeHostname } from '../onboard/hostname.js';
import { equalToken } from './auth.js';

/**
 * In-memory tunnel registry for Phase 1.
 * agentId -> { name, hostname, localUpstream, ws, registeredAt, lastSeen }
 */
const agents = new Map();
/** hostname (lower) -> agentId */
const hostIndex = new Map();

export function listAgents() {
  return [...agents.values()].map((a) => ({
    id: a.id,
    name: a.name,
    hostname: a.hostname,
    localUpstream: a.localUpstream,
    connected: Boolean(a.ws && a.ws.readyState === 1),
    registeredAt: a.registeredAt,
    lastSeen: a.lastSeen,
  }));
}

export function getAgentByHost(hostname) {
  const id = hostIndex.get(String(hostname).toLowerCase());
  if (!id) return null;
  return agents.get(id) || null;
}

export function registerAgent({ name, hostname, localUpstream, token, expectedToken, dataDir }) {
  const owner = tenantOwner(hostname, dataDir);
  const operator = equalToken(token, expectedToken);
  if (!token || (operator && owner) || (!operator && !validCredential(token, hostname, dataDir))) {
    const err = new Error('unauthorized');
    err.status = 401;
    throw err;
  }
  if (!hostname || !localUpstream) {
    const err = new Error('hostname and localUpstream required');
    err.status = 400;
    throw err;
  }
  const host = owner ? normalizeHostname(hostname) : hostname.toLowerCase();
  // Replace existing agent for same hostname
  const existingId = hostIndex.get(host);
  if (existingId) {
    const old = agents.get(existingId);
    if (old?.ws) {
      try { old.ws.close(); } catch { /* ignore */ }
    }
    agents.delete(existingId);
  }
  const id = randomUUID();
  const record = {
    id,
    name: name || `agent-${id.slice(0, 8)}`,
    hostname: host,
    localUpstream: localUpstream.replace(/\/$/, ''),
    ws: null,
    registeredAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    dataDir, credentialAuth: !operator,
    tokenHash: createHash('sha256').update(token).digest(),
  };
  agents.set(id, record);
  hostIndex.set(host, id);
  inc('registerCount');
  return {
    id: record.id,
    hostname: record.hostname,
    route: { hostname: record.hostname, via: 'tunnel', agentId: record.id },
    wsPath: '/_fastdog/tunnel',
  };
}

export function attachWs(agentId, ws, token) {
  const a = agents.get(agentId);
  if (!a || typeof token !== 'string') return false;
  const hash = createHash('sha256').update(token).digest();
  if (!timingSafeEqual(a.tokenHash, hash)) return false;
  try {
    if (a.credentialAuth && (process.env.AGENT_BOOTSTRAP_ENABLED === '1' || combined(a.dataDir ?? dataDir())) && !validCredential(token, a.hostname, a.dataDir)) return false;
  } catch { return false; }
  a.ws = ws;
  a.lastSeen = new Date().toISOString();
  return true;
}

export function touch(agentId) {
  const a = agents.get(agentId);
  if (a) a.lastSeen = new Date().toISOString();
}

export function setOriginStatus(agentId, { origin_reachable: reachable, origin_checked_at: checkedAt, agent_version: version } = {}) {
  const a = agents.get(agentId);
  if (a && validAgentVersion(version)) a.agentVersion = version;
  if (!a || typeof reachable !== 'boolean') return;
  a.originReachable = reachable;
  const parsed = Date.parse(checkedAt);
  a.originCheckedAt = Number.isFinite(parsed) ? new Date(parsed).toISOString() : new Date().toISOString();
}

export function detachWs(agentId, ws) {
  const a = agents.get(agentId);
  if (a && a.ws === ws) { a.ws = null; delete a.originReachable; delete a.originCheckedAt; }
}

/**
 * Send an HTTP-over-WS frame to the agent and wait for response.
 * Frame protocol (v0 JSON):
 *   edge -> agent: { type:'http_req', id, method, path, headers, bodyBase64? }
 *   agent -> edge: { type:'http_res', id, status, headers, bodyBase64? }
 * TODO: multiplex many streams, binary frames, backpressure, reconnect.
 */
export function proxyViaTunnel(agent, req, res) {
  if (!agent.ws || agent.ws.readyState !== 1) {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'tunnel_not_connected', hostname: agent.hostname }));
    return;
  }

  const id = randomUUID();

  function sendFrame(body) {
    const frame = {
      type: 'http_req',
      id,
      method: req.method,
      path: req.url || '/',
      headers: req.headers,
      bodyBase64: body.length ? body.toString('base64') : undefined,
    };

    const timer = setTimeout(() => {
      cleanup();
      if (!res.headersSent) {
        res.writeHead(504, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'tunnel_timeout', id }));
      }
    }, 30000);

    function onMessage(data) {
      let msg;
      try {
        msg = JSON.parse(String(data));
      } catch {
        return;
      }
      if (msg.type !== 'http_res' || msg.id !== id) return;
      cleanup();
      const headers = msg.headers || {};
      // Avoid hop-by-hop issues
      delete headers['transfer-encoding'];
      delete headers['content-length'];
      const buf = msg.bodyBase64 ? Buffer.from(msg.bodyBase64, 'base64') : Buffer.alloc(0);
      res.writeHead(msg.status || 200, { ...headers, 'content-length': buf.length });
      res.end(buf);
    }

    function cleanup() {
      clearTimeout(timer);
      agent.ws.off('message', onMessage);
    }

    agent.ws.on('message', onMessage);
    try {
      agent.ws.send(JSON.stringify(frame));
      touch(agent.id);
    } catch (err) {
      cleanup();
      if (!res.headersSent) {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'tunnel_send_failed', detail: err.message }));
      }
    }
  }

  // Defense in depth: if a prior middleware already consumed the stream (e.g. express.json),
  // 'end' will never fire again — proceed with an empty body rather than hang forever.
  if (req.readableEnded || req.complete) {
    sendFrame(Buffer.alloc(0));
    return;
  }

  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => sendFrame(Buffer.concat(chunks)));
  req.on('error', (err) => {
    if (!res.headersSent) {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'request_body_error', detail: err.message }));
    }
  });
}

export function closeHost(hostname) {
  const host = String(hostname).toLowerCase();
  const id = hostIndex.get(host);
  const agent = agents.get(id);
  hostIndex.delete(host);
  agents.delete(id);
  if (agent?.ws) {
    try { agent.ws.terminate ? agent.ws.terminate() : agent.ws.close(); } catch { /* Already closed. */ }
  }
}

export function _resetForTests() {
  agents.clear();
  hostIndex.clear();
}
