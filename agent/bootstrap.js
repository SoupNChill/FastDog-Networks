// Bootstrap redemption: durable pending request/key before any network call, bounded retries, then persisted credential.
import { randomUUID } from 'node:crypto';
import { computeBackoffMs } from './backoff.js';
import { generateKey, signExchange, decryptToken, edgeRequest, sha256, EXCHANGE_PATH } from './protocol.js';
import { writeState, probeWritable, SCHEMA_VERSION } from './state.js';

// 15-minute code lifetime plus the 120-second recovery window: the most an agent can usefully keep retrying.
export const REDEEM_HORIZON_MS = 17 * 60000;
const TERMINAL = { 400: 'bootstrap_invalid', 401: 'bootstrap_unauthorized', 409: 'bootstrap_used', 410: 'bootstrap_expired' };
export const DIAGNOSTICS = {
  bootstrap_used: 'This connection code was already redeemed by a different agent key. The code may have been copied. Revoke the agent in the portal if you do not recognise it, then request a fresh connect command (it uses a new volume).',
  bootstrap_expired: 'The connection code expired before it could be redeemed. Request a fresh connect command (it uses a new volume).',
  bootstrap_unauthorized: 'The edge did not accept this connection code for this hostname and deployment. Request a fresh connect command.',
  bootstrap_invalid: 'The edge rejected the bootstrap request as malformed. Check that the env file is unmodified, then request a fresh connect command.',
  bootstrap_rejected: 'The edge does not offer bootstrap exchange at this address. Check the connection settings or request a fresh connect command.',
  bootstrap_response_invalid: 'The edge returned an unusable bootstrap response. Request a fresh connect command.',
};

export class BootstrapError extends Error {
  constructor(code) { super(DIAGNOSTICS[code]); this.code = code; }
}

// Generates the persistent key and request (signed once; retries resend exactly these bytes) and persists them.
// Fails before any exchange if the volume cannot complete the full durable write sequence.
export function createPending({ dir, stateOpts, binding, edge, code, agentVersion, now = Date.now, keygen = generateKey }) {
  probeWritable(dir, stateOpts);
  const key = keygen();
  const request = { ...binding, request_id: randomUUID(), recipient_public_key: key.publicKey, agent_version: agentVersion };
  const digest = sha256(code);
  request.proof = signExchange(key.privateKey, edge.audience, digest, request);
  const time = now();
  const state = { schema: SCHEMA_VERSION, status: 'pending', ...binding, audience: edge.audience, private_key: key.privateKey, key_fingerprint: key.fingerprint,
    code_digest: digest, request, created_at: time, deadline_at: time + REDEEM_HORIZON_MS, next_attempt_at: time, attempt: 0 };
  writeState(dir, state, stateOpts);
  return state;
}

function complete(state, body) {
  let json;
  try { json = JSON.parse(body.toString('utf8')); } catch { throw new BootstrapError('bootstrap_response_invalid'); }
  const keys = ['credential_id', 'hostname', 'origin', 'deployment_id', 'algorithm', 'encrypted_token', 'recovery_expires_at'];
  if (!json || typeof json !== 'object' || Object.keys(json).length !== keys.length || !keys.every((k) => typeof json[k] === 'string') ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(json.credential_id) || json.algorithm !== 'RSA-OAEP-256' || json.hostname !== state.hostname ||
    json.origin !== state.origin || json.deployment_id !== state.deployment_id) throw new BootstrapError('bootstrap_response_invalid');
  let token;
  try { token = decryptToken(state.private_key, json.encrypted_token); } catch { throw new BootstrapError('bootstrap_response_invalid'); }
  // Exchange retry metadata is dropped; the private key stays with the credential for later proofs.
  return { schema: SCHEMA_VERSION, status: 'active', hostname: state.hostname, origin: state.origin, audience: state.audience,
    deployment_id: state.deployment_id, private_key: state.private_key, key_fingerprint: state.key_fingerprint,
    credential_id: json.credential_id, token, promoted: false };
}

function retryAfterMs(value) {
  const seconds = /^\d{1,6}$/.test(String(value ?? '')) ? Number(value) : NaN;
  return Number.isFinite(seconds) ? Math.max(1000, seconds * 1000) : undefined;
}

// Exchanges the persisted request until success, a terminal answer or the local deadline. Every retry decision is
// persisted first so container restarts neither reset the deadline nor hammer the endpoint.
export async function redeem({ dir, stateOpts, state, code, edge, fixture, now = Date.now, sleep, request = edgeRequest, random = Math.random, log = console }) {
  const persist = (next) => { writeState(dir, next, stateOpts); state = next; };
  const stop = (failure) => { try { persist({ ...state, failure }); } catch { /* Exit regardless; diagnostic still applies. */ } return new BootstrapError(failure); };
  for (;;) {
    if (state.failure) throw new BootstrapError(state.failure);
    if (now() >= state.deadline_at) throw stop('bootstrap_expired');
    const wait = Math.min(state.next_attempt_at, state.deadline_at) - now();
    if (wait > 0) { await sleep(wait); continue; }
    let res = null;
    try {
      res = await request(`${edge.http}${EXCHANGE_PATH}`, { method: 'POST', fixture,
        headers: { authorization: `Bearer ${code}`, 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(state.request)) });
    } catch { /* Network failure: retry the same persisted request. */ }
    if (res?.status === 200) {
      const active = complete(state, res.body);
      persist(active);
      return active;
    }
    if (res && TERMINAL[res.status]) throw stop(TERMINAL[res.status]);
    if (res && res.status !== 429 && res.status < 500) {
      // Wrong route, method or size: stop, but keep restarts from retrying immediately.
      persist({ ...state, attempt: state.attempt + 1, next_attempt_at: now() + 30000 });
      throw new BootstrapError('bootstrap_rejected');
    }
    const delay = (res?.status === 429 && retryAfterMs(res.headers['retry-after'])) || computeBackoffMs(state.attempt, { random });
    persist({ ...state, attempt: state.attempt + 1, next_attempt_at: now() + delay });
    log.warn(`[agent] bootstrap exchange unavailable${res ? ` (${res.status})` : ''}; next attempt in ${delay}ms`);
  }
}
