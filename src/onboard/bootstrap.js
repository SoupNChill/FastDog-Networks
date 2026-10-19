import { equalHash } from '../control/auth.js';
import { randomBytes, createHash, createPublicKey, publicEncrypt, verify, constants } from 'node:crypto';
import { readJson, writeJson, dataDir, enableAuthState, authTransaction } from './json.js';
import { generateCredential, tenantOwner, expireCandidates } from './credentials.js';
import { lengthPrefixed } from '../control/agent-proof.js';
import { validOrigin } from './bootstrap-origin.js';
import { normalizeHostname } from './hostname.js';
import { validAgentVersion } from '../control/agent-version.js';
import { issuerCheckFromEnv } from './issuer-check.js';

export const EXCHANGE_PATH = '/_fastdog/agents/bootstrap/exchange';
export const OAEP_LABEL = Buffer.from('fastdog-agent-bootstrap-v1');
export function clientIp(req) {
  const peer = req.socket.remoteAddress;
  if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(peer)) return peer;
  // A loopback peer without forwarding is unattributed; it shares one small bucket rather than the proxy address.
  return req.headers['x-forwarded-for']?.split(',').at(-1).trim() || null;
}
const FILE = 'agent-bootstrap.json';
const hash = (value) => createHash('sha256').update(value).digest('hex');
const error = (status, code, retry_after) => Object.assign(new Error(code), { status, code, retry_after });
const text = (s) => typeof s === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(s);
const fields = ['hostname', 'origin', 'deployment_id', 'request_id', 'recipient_public_key', 'agent_version'];
export function exchangeTranscript(audience, digest, body) {
  return lengthPrefixed(['fastdog-agent-bootstrap-v1', 'POST', EXCHANGE_PATH, audience, digest, ...fields.map((k) => body[k])]);
}
function state(directory) {
  const value = readJson(FILE, [], directory);
  return Array.isArray(value) ? { codes: [], budgets: {}, limits: {} } : value;
}
const save = (directory, value) => writeJson(FILE, value, 0o600, directory);
export function cancelBootstraps(directory, tid, host, time = Date.now()) {
  const s = state(directory);
  for (const c of s.codes) if (c.tenant_id === tid && (!host || c.hostname === host)) { c.cancelled = true; c.cancelled_at ??= time; delete c.response; }
  const credentials = readJson('agent-credentials.json', [], directory);
  for (const c of credentials) if (c.tenant_id === tid && (!host || c.claim_hostname === host) && ['pending', 'held'].includes(c.status)) c.revoked_at = new Date(time).toISOString();
  save(directory, s); writeJson('agent-credentials.json', credentials, 0o600, directory);
}
export function chargeRotation(directory, host, time, issuance = false) {
  const s = state(directory); const day = Math.floor(time / 86400000);
  const b = s.budgets[host]?.day === day ? s.budgets[host] : { day, rotations: 0, issuances: 0 };
  if (b.rotations >= 5 || (issuance && b.issuances >= 8)) throw error(429, 'rate_limited', Math.ceil(((day + 1) * 86400000 - time) / 1000));
  b.rotations++; if (issuance) b.issuances++;
  s.budgets[host] = b; save(directory, s);
}
export function createBootstrap(opts = {}) {
  const enabled = opts.bootstrapEnabled ?? process.env.AGENT_BOOTSTRAP_ENABLED === '1';
  const directory = opts.dataDir ?? dataDir(); const now = opts.now ?? Date.now;
  const audience = opts.bootstrapAudience ?? process.env.AGENT_BOOTSTRAP_AUDIENCE;
  if (enabled) enableAuthState(directory);
  // Factories inject a checker; production builds the authenticated portal client from env. None means fail closed.
  const issuerCheck = opts.issuerCheck ?? (enabled ? issuerCheckFromEnv(process.env) : undefined);
  // Maps keep insertion order, which is expiry order because every window is 60s; sweeps stop at the first live entry.
  const anonymous = new Map();
  let persistedSize = enabled ? Object.keys(state(directory).limits).length : 0;
  const capacity = Math.min(opts.limiterCapacity ?? 20000, 20000);
  function limit(table, key, maximum, otherSize) {
    const time = now(); let budget = 64;
    for (const [k, v] of table) { if (v.until > time || budget-- <= 0) break; table.delete(k); }
    let entry = table.get(key);
    if (entry && entry.until <= time) { table.delete(key); entry = undefined; }
    if (!entry && table.size + otherSize >= capacity) throw error(429, 'rate_limited', 60);
    if (!entry) table.set(key, entry = { count: 0, until: time + 60000 });
    if (entry.count >= maximum) throw error(429, 'rate_limited', Math.max(1, Math.ceil((entry.until - time) / 1000)));
    entry.count++;
  }
  let sweepCodeOffset = 0, sweepCredentialOffset = 0;
  function expire(bounded = false) {
    const s = state(directory); const credentials = readJson('agent-credentials.json', [], directory);
    let changed = false;
    const time = now();
    const codes = bounded ? s.codes.slice(sweepCodeOffset, sweepCodeOffset + 10000) : s.codes;
    const pending = bounded ? credentials.slice(sweepCredentialOffset, sweepCredentialOffset + 10000) : credentials;
    if (bounded) {
      sweepCodeOffset = sweepCodeOffset + 10000 >= s.codes.length ? 0 : sweepCodeOffset + 10000;
      sweepCredentialOffset = sweepCredentialOffset + 10000 >= credentials.length ? 0 : sweepCredentialOffset + 10000;
    }
    const remove = new Set();
    for (const c of codes) {
      const terminal = c.cancelled ? (c.cancelled_at ??= time) : c.activate_by ?? c.expires_at;
      if (time >= terminal && c.tombstone_at === undefined) { c.tombstone_at = terminal; delete c.issuer; changed = true; }
      if (c.tombstone_at !== undefined && time >= c.tombstone_at + 86400000) remove.add(c);
    }
    const retained = s.codes.filter((c) => !remove.has(c));
    if (retained.length !== s.codes.length) { s.codes = retained; changed = true; }
    for (const host of Object.keys(s.budgets)) if (s.budgets[host].day < Math.floor(time / 86400000)) { delete s.budgets[host]; changed = true; }
    for (const key of Object.keys(s.limits)) if (s.limits[key].until <= time) { delete s.limits[key]; changed = true; }
    persistedSize = Object.keys(s.limits).length;
    for (const c of codes) if (c.activate_by && now() >= c.activate_by && c.response) { delete c.response; changed = true; }
    if (expireCandidates(pending, now())) changed = true;
    if (changed) { save(directory, s); writeJson('agent-credentials.json', credentials, 0o600, directory); }
  }
  function gate() { if (!enabled) throw error(404, 'not_found'); authTransaction(directory, expire); }
  function owner(tid, host) {
    const c = tenantOwner(host, directory);
    if (!c || c.tenant_id !== tid) throw error(404, 'hostname_not_found');
    return c;
  }
  const present = (c) => ({ issuance_id: c.issuance_id, hostname: c.hostname, deployment_id: c.deployment_id,
    expires_at: new Date(c.expires_at).toISOString(), status: c.cancelled ? 'cancelled' : c.request_fingerprint ? 'used' : now() >= c.expires_at ? 'expired' : 'pending' });
  function bound(c, body) {
    const o = tenantOwner(c.hostname, directory);
    return !c.cancelled && o && o.tenant_id === c.tenant_id && o.created_at === c.claim_generation && o.credential_id === c.credential_generation &&
      c.hostname === body.hostname && c.origin === body.origin && c.deployment_id === body.deployment_id && c.audience === audience;
  }
  const sweep = enabled ? setInterval(() => {
    try { authTransaction(directory, () => expire(true)); } catch { /* Retry next sweep; never publish uncertain state. */ }
  }, opts.sweepIntervalMs ?? 30000) : undefined;
  sweep?.unref();
  // Deadlines are checked at startup too, not only by the sweep.
  if (enabled) authTransaction(directory, expire);
  const closeCandidates = (host) => { try { opts.registry?.closeCandidates?.(host); } catch { /* Durable revocation already rejects them. */ } };
  return {
    enabled, audience, issuerCheck,
    close() { clearInterval(sweep); },
    issue(tid, host, body) {
      gate();
      let fresh = false;
      const result = authTransaction(directory, () => {
        expire(); const o = owner(tid, host); const s = state(directory);
        const prior = s.codes.find((c) => c.tenant_id === tid && c.hostname === host && c.issuance_id === body.issuance_id);
        if (prior) return present(prior);
        const origin = validOrigin(body.origin);
        if (!origin || !text(body.deployment_id) || !text(body.issuance_id) || !body.issuer || !text(body.issuer.kind) || !text(body.issuer.id) ||
          !(text(body.issuer.authorization_generation) || Number.isSafeInteger(body.issuer.authorization_generation))) throw error(400, 'invalid_request');
        if (!audience) throw error(503, 'bootstrap_unavailable');
        if (s.codes.filter((c) => c.tombstone_at === undefined).length >= 10000) throw error(503, 'bootstrap_unavailable');
        chargeRotation(directory, host, now(), true);
        // Reissue cancels earlier unused codes, recovery responses and unpromoted candidates; the active credential stays.
        // Redeemed codes keep their used tombstone so different-key reuse still reports bootstrap_used.
        const credentials = readJson('agent-credentials.json', [], directory);
        for (const r of credentials) if (r.tenant_id === tid && r.claim_hostname === host && ['pending', 'held'].includes(r.status) && !r.revoked_at) r.revoked_at = new Date(now()).toISOString();
        writeJson('agent-credentials.json', credentials, 0o600, directory);
        const updated = state(directory); fresh = true;
        for (const c of updated.codes) if (c.tenant_id === tid && c.hostname === host) {
          if (!c.request_fingerprint) { c.cancelled = true; c.cancelled_at = now(); } else delete c.response;
        }
        const code = `fdab_${randomBytes(32).toString('base64url')}`;
        const c = { tenant_id: tid, hostname: host, origin, deployment_id: body.deployment_id, issuer: { kind: body.issuer.kind, id: body.issuer.id, authorization_generation: body.issuer.authorization_generation },
          issuance_id: body.issuance_id, code_hash: hash(code), expires_at: now() + 900000, audience,
          claim_generation: o.created_at, credential_generation: o.credential_id };
        updated.codes.push(c); save(directory, updated);
        return { ...present(c), code, origin };
      });
      if (fresh) closeCandidates(host);
      return result;
    },
    status(tid, host, id) {
      gate(); owner(tid, host); const c = state(directory).codes.find((c) => c.tenant_id === tid && c.hostname === host && c.issuance_id === id);
      if (!c) throw error(404, 'bootstrap_not_found'); return present(c);
    },
    cancel(tid, host) {
      gate(); const result = authTransaction(directory, () => { owner(tid, host); cancelBootstraps(directory, tid, host, now()); return { cancelled: true }; });
      closeCandidates(host); return result;
    },
    // Owner confirmation of a held candidate (portal session on the owner's behalf), scoped by (tid, hostname, credential_id).
    confirm(tid, host, id, body) {
      gate(); owner(tid, host);
      const record = readJson('agent-credentials.json', [], directory).find((r) => r.id === id && r.tenant_id === tid && r.claim_hostname === host && r.key_fingerprint !== undefined);
      if (!record) throw error(404, 'candidate_not_found');
      if (typeof body?.key_fingerprint !== 'string' || !equalHash(body.key_fingerprint, record.key_fingerprint) || record.status !== 'held' || record.revoked_at) throw error(409, 'candidate_mismatch');
      if (typeof opts.registry?.confirmCandidate !== 'function') throw error(503, 'bootstrap_unavailable');
      // The registry rechecks issuer eligibility before promoting; with an asynchronous checker the outcome is a promise.
      const finish = (outcome) => {
        if (outcome === 'promoted') return { promoted: true, credential_id: id };
        if (outcome === 'unavailable' || outcome === 'busy') throw error(503, 'bootstrap_unavailable');
        throw error(409, 'candidate_mismatch');
      };
      const outcome = opts.registry.confirmCandidate(id, body.key_fingerprint);
      return typeof outcome?.then === 'function' ? outcome.then(finish) : finish(outcome);
    },
    admit(ip) {
      if (!enabled) throw error(404, 'not_found');
      // Narrow buckets first: a rejected client must never consume shared global capacity.
      if (ip == null) limit(anonymous, 'unattributed', 10, persistedSize); else limit(anonymous, `ip:${ip}`, 30, persistedSize);
      limit(anonymous, 'global', 300, persistedSize);
    },
    async exchange(code, body, ip, signal, admitted = false) {
      if (!enabled) throw error(404, 'not_found');
      if (!admitted) this.admit(ip);
      authTransaction(directory, expire);
      const digest = hash(typeof code === 'string' ? code : '');
      let c;
      authTransaction(directory, () => {
        const s = state(directory); c = s.codes.find((c) => equalHash(c.code_hash, digest));
        if (!c) return;
        let failure; const limits = new Map(Object.entries(s.limits));
        try { limit(limits, `code:${digest}`, 10, anonymous.size); limit(limits, `claim:${c.tenant_id}:${c.hostname}`, 30, anonymous.size); } catch (e) { failure = e; }
        s.limits = Object.fromEntries(limits); persistedSize = limits.size; save(directory, s);
        if (failure) c = { failure };
      });
      if (c?.failure) throw c.failure;
      if (!c) throw error(401, 'unauthorized');
      if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some((k) => ![...fields, 'proof'].includes(k)) ||
        !validAgentVersion(body.agent_version) || !text(body.request_id) || !text(body.deployment_id) || typeof body.recipient_public_key !== 'string' || body.recipient_public_key.length > 2048 ||
        typeof body.origin !== 'string' || typeof body.proof !== 'string' || !/^[A-Za-z0-9_-]{512}$/.test(body.proof) || validOrigin(body.origin) !== body.origin) throw error(400, 'invalid_request');
      try { if (normalizeHostname(body.hostname) !== body.hostname) throw 0; } catch { throw error(400, 'invalid_request'); }
      let key, der;
      try {
        if (!body.recipient_public_key.startsWith('-----BEGIN PUBLIC KEY-----')) throw 0;
        key = createPublicKey(body.recipient_public_key);
        if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails.modulusLength !== 3072 || key.asymmetricKeyDetails.publicExponent !== 65537n) throw 0;
        der = key.export({ type: 'spki', format: 'der' });
      } catch { throw error(400, 'invalid_request'); }
      if (!c || !bound(c, body)) throw error(401, 'unauthorized');
      const transcript = exchangeTranscript(audience, digest, body);
      if (!verify('sha256', transcript, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, Buffer.from(body.proof, 'base64url'))) throw error(401, 'unauthorized');
      const fingerprint = hash(transcript), keyFingerprint = hash(der);
      function classify(current) {
        if (!current || !bound(current, body)) throw error(401, 'unauthorized');
        if (current.request_fingerprint) {
          if (!equalHash(current.request_fingerprint, fingerprint) || !equalHash(current.key_fingerprint, keyFingerprint)) throw error(409, 'bootstrap_used');
          const credential = readJson('agent-credentials.json', [], directory).find((r) => r.id === current.credential_id);
          if (now() >= current.activate_by) throw error(410, 'bootstrap_expired');
          if (!current.response || !credential || credential.revoked_at) throw error(401, 'unauthorized');
        } else if (now() >= current.expires_at) throw error(410, 'bootstrap_expired');
      }
      classify(c);
      if (typeof issuerCheck !== 'function') throw error(503, 'bootstrap_unavailable');
      let authorized;
      let timer;
      try { authorized = await Promise.race([issuerCheck(structuredClone(c.issuer), { signal }), new Promise((_, reject) => {
        timer = setTimeout(() => reject(error(503, 'bootstrap_unavailable')), 5000);
      })]); } catch { throw error(503, 'bootstrap_unavailable'); } finally { clearTimeout(timer); }
      if (authorized === false) throw error(401, 'unauthorized');
      if (authorized !== true) throw error(503, 'bootstrap_unavailable');
      if (signal?.aborted) throw error(503, 'bootstrap_unavailable');
      // Recheck after the only asynchronous boundary, under the same synchronous writer lock.
      return authTransaction(directory, () => {
        expire(); const s = state(directory); c = s.codes.find((r) => equalHash(r.code_hash, digest)); classify(c);
        if (c.response) return c.response;
        const { token, record } = generateCredential({ tenant_id: c.tenant_id, hostname: c.hostname }, now);
        const activateBy = now() + 120000;
        // The bound public key verifies later register/WS proofs; hold_until bounds an unpromoted candidate to one hour.
        // The issuer (kind, ID, generation only) is kept for the candidate and promotion rechecks.
        Object.assign(record, { status: 'pending', key_fingerprint: keyFingerprint, public_key: der.toString('base64'), activate_by: activateBy, hold_until: now() + 3600000,
          issuer: structuredClone(c.issuer) });
        const credentials = readJson('agent-credentials.json', [], directory); credentials.push(record);
        const response = { credential_id: record.id, hostname: c.hostname, origin: c.origin, deployment_id: c.deployment_id, algorithm: 'RSA-OAEP-256',
          encrypted_token: publicEncrypt({ key, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: OAEP_LABEL }, Buffer.from(token)).toString('base64url'), recovery_expires_at: new Date(activateBy).toISOString() };
        Object.assign(c, { request_fingerprint: fingerprint, key_fingerprint: keyFingerprint, credential_id: record.id, redeemed_at: now(), activate_by: activateBy, response });
        writeJson('agent-credentials.json', credentials, 0o600, directory); save(directory, s); return response;
      });
    },
  };
}

export function bootstrapHandler(service) {
  return async (req, res) => {
    const send = (status, body, retry) => { if (!res.writableEnded) { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...(retry ? { 'retry-after': String(retry) } : {}) }); res.end(JSON.stringify(body)); } };
    if (!service.enabled || req.url !== EXCHANGE_PATH) return send(404, { error: 'not_found' });
    if (req.method !== 'POST') return send(405, { error: 'method_not_allowed' });
    const abort = new AbortController();
    const timer = setTimeout(() => { abort.abort(); send(503, { error: 'bootstrap_unavailable' }); }, 5000);
    res.once('close', () => abort.abort());
    try {
      service.admit(clientIp(req));
      if (Number(req.headers['content-length']) > 16384) throw error(413, 'payload_too_large');
      const chunks = []; let size = 0;
      const body = await new Promise((resolve, reject) => {
        req.on('data', (chunk) => { size += chunk.length; if (size > 16384) { reject(error(413, 'payload_too_large')); return; } chunks.push(chunk); });
        req.on('error', () => resolve(null));
        abort.signal.addEventListener('abort', () => reject(error(503, 'bootstrap_unavailable')), { once: true });
        req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { resolve(null); } });
      });
      const code = /^Bearer (fdab_[A-Za-z0-9_-]{43})$/.exec(req.headers.authorization ?? '')?.[1];
      send(200, await service.exchange(code, body, clientIp(req), abort.signal, true));
    } catch (e) { const known = [400, 401, 409, 410, 413, 429, 503].includes(e.status); send(known ? e.status : 503, { error: known ? e.code : 'bootstrap_unavailable' }, e.retry_after); }
    finally { clearTimeout(timer); }
  };
}

export function bootstrapMiddleware(service) {
  const handler = bootstrapHandler(service);
  let authority;
  try { const url = new URL(service.audience); if (url.protocol === 'https:') authority = url.host.toLowerCase(); } catch { /* Missing configuration fails closed. */ }
  return (req, res, next) => service.enabled && authority && req.url === EXCHANGE_PATH && req.headers.host?.toLowerCase() === authority ? handler(req, res) : next();
}
