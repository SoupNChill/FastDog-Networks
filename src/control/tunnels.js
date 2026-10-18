import { combined, dataDir as defaultDataDir } from '../onboard/json.js';
import { validAgentVersion } from './agent-version.js';
import { randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { inc } from '../lib/metrics.js';
import { validCredential, tenantOwner } from '../onboard/credentials.js';
import { validCandidateCredential, candidateLive, promoteCandidate } from '../onboard/candidates.js';
import { normalizeHostname } from '../onboard/hostname.js';
import { equalToken, equalHash } from './auth.js';

/**
 * In-memory tunnel registry for Phase 1.
 * agentId -> { name, hostname, localUpstream, ws, registeredAt, lastSeen }
 */
const agents = new Map();
/** hostname (lower) -> agentId */
const hostIndex = new Map();

// Bootstrap candidates (AGENT_BOOTSTRAP_ENABLED only). Routing, hostIndex, listAgents and getAgentByHost never read these;
// only promotion moves a candidate into `agents`.
/** credential id -> { id, credentialId, tenantId, keyFingerprint, hostname, localUpstream, ws, ready, ... } */
const candidates = new Map();
/** candidate agentId -> credential id */
const candidateAgents = new Map();
/** hostname -> time the active tunnel last detached; absent entries count from process start */
const absentSince = new Map();
export const DEFAULT_ABSENT_FOR_MS = 300000;
let candidateMode = false, clock = Date.now, absentForMs = DEFAULT_ABSENT_FOR_MS, startedAt = Date.now();

// Seconds from AGENT_BOOTSTRAP_ABSENT_FOR_SECONDS: unset means 300; otherwise an integer 60-3600.
export function absentForSetting(value) {
  if (value === undefined || value === '') return DEFAULT_ABSENT_FOR_MS;
  const seconds = Number(value);
  if (!Number.isInteger(seconds) || seconds < 60 || seconds > 3600) throw new Error('AGENT_BOOTSTRAP_ABSENT_FOR_SECONDS must be an integer from 60 to 3600');
  return seconds * 1000;
}

export function configureCandidates({ enabled = true, now = Date.now, absentForMs: absent = DEFAULT_ABSENT_FOR_MS } = {}) {
  candidateMode = enabled; clock = now; absentForMs = absent; startedAt = now();
}

const unauthorized = () => Object.assign(new Error('unauthorized'), { status: 401 });
function closeSocket(ws, code) {
  try { if (ws) code ? ws.close(code, 'unauthorized') : ws.terminate ? ws.terminate() : ws.close(); } catch { /* Already closed. */ }
}
const connected = (ws) => Boolean(ws && ws.readyState === 1);
function notify(c, state) {
  try { if (connected(c.ws)) c.ws.send(JSON.stringify({ type: 'candidate_status', state })); } catch { /* Socket closing. */ }
}

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

// `candidate` and `proof` are supplied only when bootstrap is enabled; legacy callers pass neither.
export function registerAgent({ name, hostname, localUpstream, token, expectedToken, dataDir, candidate = false, proof }) {
  if (candidate) return registerCandidate({ name, hostname, localUpstream, token, dataDir, proof });
  const owner = tenantOwner(hostname, dataDir);
  const operator = equalToken(token, expectedToken);
  if (!token || (operator && owner) || (!operator && !validCredential(token, hostname, dataDir, clock, proof))) {
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
      if (candidateMode && connected(old.ws)) absentSince.set(host, clock());
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

function registerCandidate({ name, hostname, localUpstream, token, dataDir, proof }) {
  let record = null;
  try { record = validCandidateCredential(token, hostname, dataDir, clock, proof); } catch { /* Storage uncertainty fails closed. */ }
  if (!record) throw unauthorized();
  if (!localUpstream) throw Object.assign(new Error('hostname and localUpstream required'), { status: 400 });
  // Re-registration replaces only this credential's own earlier candidate.
  const previous = candidates.get(record.id);
  if (previous) { candidateAgents.delete(previous.id); closeSocket(previous.ws); }
  const id = randomUUID(); const time = new Date().toISOString();
  candidates.set(record.id, { id, credentialId: record.id, tenantId: record.tenant_id, keyFingerprint: record.key_fingerprint,
    name: name || `agent-${id.slice(0, 8)}`, hostname: record.claim_hostname, localUpstream: localUpstream.replace(/\/$/, ''),
    ws: null, ready: false, registeredAt: time, lastSeen: time, dataDir, tokenHash: createHash('sha256').update(token).digest() });
  candidateAgents.set(id, record.id);
  return { id, hostname: record.claim_hostname, candidate: true, state: record.status, wsPath: '/_fastdog/tunnel' };
}

function attachCandidate(agentId, ws, token, proof) {
  const c = candidates.get(candidateAgents.get(agentId));
  if (!c || typeof token !== 'string' || !timingSafeEqual(c.tokenHash, createHash('sha256').update(token).digest())) return false;
  let record = null;
  try { record = validCandidateCredential(token, c.hostname, c.dataDir, clock, proof); } catch { /* Fail closed. */ }
  if (record?.id !== c.credentialId) return false;
  if (c.ws && c.ws !== ws) closeSocket(c.ws);
  c.ws = ws; c.ready = false;
  c.lastSeen = new Date().toISOString();
  return true;
}

export function attachWs(agentId, ws, token, { candidate = false, proof } = {}) {
  if (candidate) return attachCandidate(agentId, ws, token, proof);
  const a = agents.get(agentId);
  if (!a || typeof token !== 'string') return false;
  const hash = createHash('sha256').update(token).digest();
  if (!timingSafeEqual(a.tokenHash, hash)) return false;
  try {
    if (a.credentialAuth && (process.env.AGENT_BOOTSTRAP_ENABLED === '1' || combined(a.dataDir ?? defaultDataDir())) && !validCredential(token, a.hostname, a.dataDir, clock, proof)) return false;
  } catch { return false; }
  a.ws = ws;
  a.lastSeen = new Date().toISOString();
  // Any reattachment of the active agent resets the absence clock.
  if (candidateMode && hostIndex.get(a.hostname) === agentId) absentSince.delete(a.hostname);
  return true;
}

function dropCandidate(credentialId) {
  const c = candidates.get(credentialId);
  if (!c) return;
  candidates.delete(credentialId); candidateAgents.delete(c.id);
  closeSocket(c.ws, 4401);
}

// Moves a promoted candidate into the active registry and closes the replaced agent's socket.
function install(c) {
  const oldId = hostIndex.get(c.hostname); const old = agents.get(oldId);
  candidates.delete(c.credentialId); candidateAgents.delete(c.id);
  agents.set(c.id, { id: c.id, name: c.name, hostname: c.hostname, localUpstream: c.localUpstream, ws: c.ws,
    registeredAt: c.registeredAt, lastSeen: c.lastSeen, dataDir: c.dataDir, credentialAuth: true, tokenHash: c.tokenHash });
  hostIndex.set(c.hostname, c.id);
  absentSince.delete(c.hostname);
  if (old && oldId !== c.id) { agents.delete(oldId); closeSocket(old.ws); }
}

// Promotion hold: promote a ready candidate only on owner confirmation, or when the active tunnel is not connected and
// has been continuously absent for absent_for (or there is no active credential). Otherwise it is held without traffic.
function evaluate(credentialId, { confirmed = false, keyFingerprint } = {}) {
  const c = candidates.get(credentialId);
  if (!c?.ready || !connected(c.ws)) return 'not_ready';
  const active = agents.get(hostIndex.get(c.hostname));
  const activeConnected = connected(active?.ws);
  const since = Math.max(absentSince.get(c.hostname) ?? startedAt, startedAt);
  let result;
  try {
    result = promoteCandidate(c.dataDir, credentialId, clock, { activeConnected, absentLongEnough: !activeConnected && clock() - since >= absentForMs, confirmed, keyFingerprint });
  } catch { return 'unavailable'; }
  if (result.state === 'invalid') { dropCandidate(credentialId); return 'invalid'; }
  if (result.state === 'promoted') install(c);
  if (result.state !== 'mismatch') notify(c, result.state);
  return result.state;
}

// Called after the candidate's WS welcome: authenticated attachment plus welcome makes it ready.
export function candidateReady(agentId, ws) {
  const c = candidates.get(candidateAgents.get(agentId));
  if (!c || c.ws !== ws) return 'not_ready';
  c.ready = true;
  return evaluate(c.credentialId);
}

export function confirmCandidate(credentialId, keyFingerprint) {
  const c = candidates.get(credentialId);
  if (!c || !equalHash(c.keyFingerprint, keyFingerprint)) return 'not_ready';
  return evaluate(credentialId, { confirmed: true, keyFingerprint });
}

export function closeCandidates(hostname) {
  const host = String(hostname).toLowerCase();
  for (const c of [...candidates.values()]) if (c.hostname === host) dropCandidate(c.credentialId);
}

// Periodic (enabled only): promote held candidates whose active tunnel stayed absent; drop expired or revoked ones.
export function sweepCandidates() {
  for (const c of [...candidates.values()]) {
    if (c.ready && connected(c.ws)) { evaluate(c.credentialId); continue; }
    let alive = false;
    try { alive = candidateLive(c.dataDir, c.credentialId, clock); } catch { continue; }
    if (!alive) dropCandidate(c.credentialId);
  }
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
  if (a && a.ws === ws) {
    a.ws = null; delete a.originReachable; delete a.originCheckedAt;
    if (candidateMode && hostIndex.get(a.hostname) === agentId) absentSince.set(a.hostname, clock());
    return;
  }
  // A disconnected candidate returns to pending semantics and may reattach until its deadline.
  const c = candidates.get(candidateAgents.get(agentId));
  if (c && c.ws === ws) { c.ws = null; c.ready = false; }
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
  // Every revocation path removes the host's candidates too.
  if (candidateMode) absentSince.set(host, clock());
  closeCandidates(host);
}

export function _resetForTests() {
  agents.clear();
  hostIndex.clear();
  candidates.clear(); candidateAgents.clear(); absentSince.clear();
  configureCandidates({ enabled: false });
}
