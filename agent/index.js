/**
 * Fastdog tunnel agent.
 *
 * Outbound connector: registers with edge control API, opens WebSocket,
 * receives HTTP-over-WS frames, fetches AGENT_LOCAL_UPSTREAM, returns response.
 *
 * Credentials: a persisted key-bound credential in the state volume, a one-time AGENT_BOOTSTRAP code redeemed into
 * that volume, or the legacy AGENT_TOKEN compatibility mode. The credential is held in memory only.
 *
 * Enough shape to eventually replace cloudflared for Summit Lease dogfood.
 * TODO: multiplex streams, binary frames, multi-host, CONNECT/WebSocket upgrade passthrough.
 */
import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';
import WebSocket from 'ws';
import { computeBackoffMs } from './backoff.js';
import { startHeartbeat } from './heartbeat.js';
import { readSettings, pinnedEdge, bootstrapBinding, requiredBinding, loadPins } from './config.js';
import { STATE_DIR, stateExists, readState, writeState, acquireLock, removeAbandonedTemps } from './state.js';
import { createPending, redeem } from './bootstrap.js';
import { REGISTER_PATH, PROOF_HEADER, proofHeader, edgeRequest, dialTarget, tlsOptions, sha256 } from './protocol.js';

function env(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

const LOCAL_UPSTREAM = env('AGENT_LOCAL_UPSTREAM', 'http://127.0.0.1:9999').replace(/\/$/, '');

// Legacy bearer credentials keep the 0.1.2 transport exactly; key-bound credentials add a fresh proof per request.
export async function register(credential, settings) {
  if (credential.mode !== 'key_bound') {
    const res = await fetch(`${settings.edgeHttp.replace(/\/$/, '')}/_fastdog/agents/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${credential.token}` },
      body: JSON.stringify({ name: settings.name, hostname: settings.hostname, localUpstream: settings.localUpstream }),
    });
    if (!res.ok) throw Object.assign(new Error(`register failed: ${res.status}`), { status: res.status });
    return res.json();
  }
  const target = `${REGISTER_PATH}${credential.candidate ? '?candidate=1' : ''}`;
  const body = Buffer.from(JSON.stringify({ name: settings.name, hostname: settings.hostname, localUpstream: settings.localUpstream }));
  const res = await edgeRequest(`${settings.edge.http}${target}`, {
    fixture: settings.fixture?.http, body,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${credential.token}`,
      [PROOF_HEADER]: proofHeader(credential.privateKey, { method: 'POST', target, audience: credential.audience, credentialId: credential.credentialId, body }) },
  });
  if (res.status < 200 || res.status >= 300) throw Object.assign(new Error(`register failed: ${res.status}`), { status: res.status });
  return JSON.parse(res.body.toString('utf8'));
}

function fetchLocal(upstream, method, path, headers, bodyBuf) {
  return new Promise((resolve, reject) => {
    const target = new URL(path || '/', upstream);
    const isHttps = target.protocol === 'https:';
    const lib = isHttps ? https : http;
    // Preserve client Host from the edge (Host-based apps); only use the upstream for TCP.
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

// Reachability probe of the operator's own local app only. Any HTTP response means the app is listening; the
// result is a boolean and no response content is read. Do not reuse this (TLS checks off) for forwarded traffic.
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
// Reported in heartbeats so the portal can tell which agent version is connected.
export const AGENT_VERSION = (() => {
  for (const rel of ['./package.json', '../package.json']) {
    try {
      const pkg = JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8'));
      if (pkg.name === 'fastdog-agent' && /^\d+\.\d+\.\d+$/.test(pkg.version)) return pkg.version;
    } catch { /* try the next location */ }
  }
  return null;
})();
let originStatus = {};
// Nonsecret credential diagnostics only: the mode and bootstrap progress, never state contents.
let credentialStatus = {};
async function refreshOrigin(upstream) {
  originStatus = { origin_reachable: await probeOrigin(upstream), origin_checked_at: new Date().toISOString(),
    ...(AGENT_VERSION ? { agent_version: AGENT_VERSION } : {}) };
}
export const currentOriginStatus = () => ({ ...originStatus, ...credentialStatus });
const setCredentialStatus = (mode, status) => { credentialStatus = { credential_mode: mode, bootstrap_status: status }; };

async function handleFrame(ws, msg, upstream) {
  if (msg.type !== 'http_req') return;
  try {
    const bodyBuf = msg.bodyBase64 ? Buffer.from(msg.bodyBase64, 'base64') : null;
    const result = await fetchLocal(upstream, msg.method, msg.path, msg.headers || {}, bodyBuf);
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

function openSocket(credential, agentId, settings) {
  if (credential.mode !== 'key_bound') {
    const u = new URL(settings.edgeWs);
    u.searchParams.set('agentId', agentId);
    u.searchParams.delete('token');
    return new WebSocket(u.toString(), { headers: { Authorization: `Bearer ${credential.token}` } });
  }
  // The exact target (agentId and candidate selector) is signed; TLS is verified and redirects are refused.
  const pinned = new URL(settings.edge.ws);
  const target = `${pinned.pathname}?agentId=${encodeURIComponent(agentId)}${credential.candidate ? '&candidate=1' : ''}`;
  const { url, secure } = dialTarget(`${pinned.origin}${target}`, settings.fixture?.ws);
  return new WebSocket(url.toString(), {
    followRedirects: false, ...(secure ? tlsOptions() : {}),
    headers: { Authorization: `Bearer ${credential.token}`,
      [PROOF_HEADER]: proofHeader(credential.privateKey, { method: 'GET', target, audience: credential.audience, credentialId: credential.credentialId }) },
  });
}

export function connectWs(credential, agentId, onWelcome, settings, { onCandidateStatus } = {}) {
  return new Promise((resolve) => {
    let ws;
    try { ws = openSocket(credential, agentId, settings); } catch { console.error('[agent] connection error'); resolve(); return; }
    activeSocket = ws;
    ws.on('open', () => {
      console.log('[agent] tunnel connected');
      refreshOrigin(settings.localUpstream);
      const probe = setInterval(() => refreshOrigin(settings.localUpstream), 20000);
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
      if (msg.type === 'candidate_status') { if (credential.mode === 'key_bound') onCandidateStatus?.(msg.state); return; }
      handleFrame(ws, msg, settings.localUpstream);
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
      if (err?.fatal) throw err;
      console.error('[agent] registration or connection failed. Check the connection settings.');
    }
    const nextDelay = backoff(attempt);
    console.warn(`[agent] reconnect attempt ${attempt + 1}, next delay ${nextDelay}ms`);
    attempt += 1;
    await delay(nextDelay);
  }
}

const fatal = (code, message) => Object.assign(new Error(message), { code, fatal: true });
// Consecutive rejections across both registration modes before concluding the credential is revoked or expired.
export const MAX_CREDENTIAL_REJECTIONS = 3;

// Candidate registration until the edge reports promotion (or the active path accepts the credential), then active.
function keyBoundLoop({ credential, settings, persistPromoted, loop }) {
  let rejected = 0, noticed = false;
  const held = () => {
    setCredentialStatus('key_bound', 'held');
    if (!noticed) console.log(`[agent] awaiting owner confirmation or old-agent absence; this agent's key fingerprint is ${credential.fingerprint}`);
    noticed = true;
  };
  const promoted = () => {
    setCredentialStatus('key_bound', 'promoted');
    if (credential.promoted) return;
    credential.promoted = true; console.log('[agent] credential promoted; this agent now serves the hostname');
    persistPromoted();
  };
  const attemptRegister = async (candidate) => {
    const reg = await register({ ...credential, candidate }, settings);
    rejected = 0;
    return reg;
  };
  let candidateRegistration = false;
  return loop({
    registerAgent: async () => {
      if (!credential.promoted) {
        try {
          const reg = await attemptRegister(true);
          candidateRegistration = true; noticed = false;
          if (reg.state === 'held') held(); else setCredentialStatus('key_bound', 'candidate');
          return reg;
        } catch (e) { if (e.status !== 401) throw e; }
      }
      try {
        const reg = await attemptRegister(false);
        candidateRegistration = false; promoted();
        return reg;
      } catch (e) {
        if (e.status === 401 && ++rejected >= MAX_CREDENTIAL_REJECTIONS) {
          throw fatal('credential_rejected', 'The edge no longer accepts the saved credential (revoked, replaced or not activated in time). Request a fresh connect command; it uses a new volume.');
        }
        throw e;
      }
    },
    connect: (id, onWelcome) => connectWs({ ...credential, candidate: candidateRegistration }, id, onWelcome, settings, {
      onCandidateStatus: (state) => { if (state === 'held') held(); else if (state === 'promoted') promoted(); },
    }),
  });
}

// The volume lock of the current startAgent, so a signal during startup (for example while redeem sleeps) releases it.
let heldLock;
export function releaseVolumeLock() { heldLock?.release(); }

const sameBinding = (state, binding, audience) =>
  state.hostname === binding.hostname && state.origin === binding.origin && state.deployment_id === binding.deployment_id && state.audience === audience;

/**
 * Startup state machine (plan section 5): env schema; persisted credential; bootstrap; legacy token; else fail.
 * Test seams (stateDir, pins, fixture, fs, uid, clock, keygen, request, loop) are code-only, never env-selectable.
 * Resolves `{ code }` after a failure (exit(1) already called) or `{ mode, loop, stop }` once the tunnel loop runs.
 */
export async function startAgent(opts = {}) {
  const log = opts.log ?? console;
  const exit = opts.exit ?? ((code) => process.exit(code));
  const dir = opts.stateDir ?? STATE_DIR;
  const stateOpts = { fs: opts.fs, uid: opts.uid };
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  let lock, stopped = false;
  const fail = (code, message) => {
    log.error(`[agent] ${code}: ${message}`);
    lock?.release();
    exit(1);
    return { code };
  };
  const failWith = (e) => fail(e.code ?? 'startup_failed', e.code && e.message ? e.message : 'The agent could not start.');

  let settings, exists;
  try {
    const env = opts.env ?? process.env;
    const set = (name) => env[name] !== undefined && env[name] !== '';
    // Token-only startups keep 0.1.2's leniency (unreadable state directory, extra AGENT_* names) unless a saved
    // state exists, in which case the key-bound rules apply.
    const legacy = set('AGENT_TOKEN') && !set('AGENT_BOOTSTRAP');
    exists = stateExists(dir, { ...stateOpts, legacy });
    settings = readSettings(env, { legacy: legacy && !exists });
  } catch (e) { return failWith(e); }
  const halted = () => Object.assign(new Error('stopped'), { fatal: true, stopped: true });
  const delay = (ms) => (stopped ? Promise.reject(halted()) : sleep(ms));
  // A stop during an in-flight registration must not open a new tunnel afterwards.
  const loop = (fns) => (opts.loop ?? reconnectLoop)({ delay,
    registerAgent: async () => { const reg = await fns.registerAgent(); if (stopped) throw halted(); return reg; },
    connect: (id, onWelcome) => (stopped ? Promise.reject(halted()) : fns.connect(id, onWelcome)) });
  const stop = () => {
    stopped = true;
    try { activeSocket?.close(1000, 'shutdown'); } catch { /* Already closed. */ }
    lock?.release();
  };
  const running = (mode, promise) => ({ mode, stop, loop: promise.catch((e) => {
    if (!e?.stopped) fail(e.code ?? 'agent_failed', e.code ? e.message : 'The agent stopped unexpectedly.');
  }) });

  if (exists || settings.bootstrap) {
    if (!exists && settings.token) return fail('ambiguous_config', 'Both AGENT_BOOTSTRAP and AGENT_TOKEN are set and no saved credential exists. Use exactly one.');
    let edge, binding, state;
    try {
      edge = pinnedEdge(settings, opts.pins ?? loadPins());
      binding = requiredBinding(settings);
      lock = await acquireLock(dir, { ...stateOpts, ...opts.lockOptions, onLost: () => fail('volume_lock_lost', 'The credential state volume lock was lost.') });
      heldLock = lock;
      removeAbandonedTemps(dir, stateOpts);
      if (stateExists(dir, stateOpts)) {
        // Persisted state always wins over env; it must match this deployment exactly or startup fails closed.
        state = readState(dir, stateOpts);
        if (!sameBinding(state, binding, edge.audience)) return fail('state_binding_mismatch', 'The saved credential belongs to a different hostname, origin, edge or deployment. Use the volume named in the connect command.');
        if (state.status === 'pending') {
          if (!settings.bootstrap) return fail('state_pending_without_bootstrap', 'A bootstrap exchange was started in this volume but AGENT_BOOTSTRAP is no longer set.');
          bootstrapBinding(settings);
          if (state.code_digest !== sha256(settings.bootstrap)) return fail('state_binding_mismatch', 'The saved bootstrap request was made with a different connection code. Use the volume named in the connect command.');
        }
      } else {
        bootstrapBinding(settings);
        if (!opts.agentVersion && !AGENT_VERSION) return fail('version_unknown', 'The agent package version is unavailable.');
        state = createPending({ dir, stateOpts, binding, edge, code: settings.bootstrap, agentVersion: opts.agentVersion ?? AGENT_VERSION, now, keygen: opts.keygen });
      }
      if (state.status === 'pending') {
        log.log('[agent] redeeming connection code');
        state = await redeem({ dir, stateOpts, state, code: settings.bootstrap, edge, fixture: opts.fixture?.exchange ?? opts.fixture?.http,
          now, sleep, request: opts.request, random: opts.random, log });
        log.log('[agent] credential saved');
      }
    } catch (e) { return failWith(e); }
    const credential = { mode: 'key_bound', token: state.token, credentialId: state.credential_id, privateKey: state.private_key,
      fingerprint: state.key_fingerprint, audience: edge.audience, promoted: state.promoted };
    setCredentialStatus('key_bound', state.promoted ? 'promoted' : 'candidate');
    const run = { ...settings, edge, fixture: opts.fixture };
    const persistPromoted = () => {
      try { state = { ...state, promoted: true }; writeState(dir, state, stateOpts); } catch { log.warn('[agent] could not save promotion; will re-check on restart'); }
    };
    return running('key_bound', keyBoundLoop({ credential, settings: run, persistPromoted, loop }));
  }
  if (settings.token?.trim()) {
    log.warn('[agent] AGENT_TOKEN compatibility mode is deprecated: the connection token stays in the container configuration. Request a new connect command to switch to a bootstrap credential.');
    setCredentialStatus('legacy', 'none');
    const credential = { mode: 'legacy', token: settings.token };
    return running('legacy', loop({ registerAgent: () => register(credential, settings), connect: (id, onWelcome) => connectWs(credential, id, onWelcome, settings) }));
  }
  return fail('missing_credential', 'AGENT_TOKEN is required, or AGENT_BOOTSTRAP with a credential state volume. Set the connection settings before starting.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href && process.env.FASTDOG_AGENT_NO_MAIN !== '1') {
  // Every agent write (state, lock, temps) is private to this user.
  process.umask(0o077);
  const started = startAgent();
  let agent;
  const stop = () => {
    agent?.stop?.();
    releaseVolumeLock();
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
  started.then((result) => { agent = result; });
}
