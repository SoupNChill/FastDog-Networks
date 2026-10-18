import { randomBytes, createHash, createPublicKey, publicEncrypt, verify, constants, timingSafeEqual } from 'node:crypto';
import { readJson, writeJson, dataDir, enableAuthState, authTransaction } from './json.js';
import { generateCredential, tenantOwner } from './credentials.js';
import { validOrigin } from './bootstrap-origin.js';
import { normalizeHostname } from './hostname.js';
import { validAgentVersion } from '../control/agent-version.js';

export const EXCHANGE_PATH = '/_fastdog/agents/bootstrap/exchange';
export const OAEP_LABEL = Buffer.from('fastdog-agent-bootstrap-v1');
const FILE = 'agent-bootstrap.json';
const hash = (value) => createHash('sha256').update(value).digest('hex');
const error = (status, code, retry_after) => Object.assign(new Error(code), { status, code, retry_after });
const text = (s) => typeof s === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(s);
const fields = ['hostname', 'origin', 'deployment_id', 'request_id', 'recipient_public_key', 'agent_version'];
export function exchangeTranscript(audience, digest, body) {
  return Buffer.concat(['fastdog-agent-bootstrap-v1', 'POST', EXCHANGE_PATH, audience, digest, ...fields.map((k) => body[k])].map((value) => {
    const bytes = Buffer.from(value); const size = Buffer.alloc(4); size.writeUInt32BE(bytes.length); return Buffer.concat([size, bytes]);
  }));
}
function state(directory) {
  const value = readJson(FILE, [], directory);
  return Array.isArray(value) ? { codes: [], budgets: {}, limits: {} } : value;
}
const save = (directory, value) => writeJson(FILE, value, 0o600, directory);
export function cancelBootstraps(directory, tid, host, time = Date.now()) {
  const s = state(directory);
  for (const c of s.codes) if (c.tenant_id === tid && (!host || c.hostname === host)) { c.cancelled = true; delete c.response; }
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
  const anonymous = {};
  const capacity = Math.min(opts.limiterCapacity ?? 20000, 20000);
  function limit(table, key, maximum, other = {}) {
    const time = now();
    for (const k of Object.keys(table)) if (table[k].until <= time) delete table[k];
    for (const k of Object.keys(other)) if (other[k].until <= time) delete other[k];
    if (!table[key] && Object.keys(table).length + Object.keys(other).length >= capacity) throw error(429, 'rate_limited', 60);
    const entry = table[key] ??= { count: 0, until: time + 60000 };
    if (entry.count >= maximum) throw error(429, 'rate_limited', Math.max(1, Math.ceil((entry.until - time) / 1000)));
    entry.count++;
  }
  function expire() {
    const s = state(directory); const credentials = readJson('agent-credentials.json', [], directory);
    let changed = false;
    for (const c of s.codes) if (c.activate_by && now() >= c.activate_by && c.response) { delete c.response; changed = true; }
    for (const c of credentials) if (c.status === 'pending' && now() >= c.activate_by && !c.revoked_at) { c.revoked_at = new Date(now()).toISOString(); changed = true; }
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
  return {
    enabled,
    issue(tid, host, body) {
      gate();
      return authTransaction(directory, () => {
        const o = owner(tid, host); const s = state(directory);
        const prior = s.codes.find((c) => c.tenant_id === tid && c.hostname === host && c.issuance_id === body.issuance_id);
        if (prior) return present(prior);
        const origin = validOrigin(body.origin);
        if (!origin || !text(body.deployment_id) || !text(body.issuance_id) || !body.issuer || !text(body.issuer.kind) || !text(body.issuer.id) ||
          !(text(body.issuer.authorization_generation) || Number.isSafeInteger(body.issuer.authorization_generation))) throw error(400, 'invalid_request');
        if (!audience) throw error(503, 'bootstrap_unavailable');
        chargeRotation(directory, host, now(), true);
        const updated = state(directory);
        for (const c of updated.codes) if (c.tenant_id === tid && c.hostname === host && !c.request_fingerprint) c.cancelled = true;
        const code = `fdab_${randomBytes(32).toString('base64url')}`;
        const c = { tenant_id: tid, hostname: host, origin, deployment_id: body.deployment_id, issuer: { kind: body.issuer.kind, id: body.issuer.id, authorization_generation: body.issuer.authorization_generation },
          issuance_id: body.issuance_id, code_hash: hash(code), expires_at: now() + 900000, audience,
          claim_generation: o.created_at, credential_generation: o.credential_id };
        updated.codes.push(c); save(directory, updated);
        return { ...present(c), code, origin };
      });
    },
    status(tid, host, id) {
      gate(); const c = state(directory).codes.find((c) => c.tenant_id === tid && c.hostname === host && c.issuance_id === id);
      if (!c) throw error(404, 'bootstrap_not_found'); return present(c);
    },
    cancel(tid, host) { gate(); return authTransaction(directory, () => { owner(tid, host); cancelBootstraps(directory, tid, host, now()); return { cancelled: true }; }); },
    admit(ip) {
      if (!enabled) throw error(404, 'not_found');
      const persistedLimits = state(directory).limits;
      limit(anonymous, 'global', 300, persistedLimits); limit(anonymous, `ip:${ip}`, 30, persistedLimits);
    },
    async exchange(code, body, ip, signal, admitted = false) {
      if (!enabled) throw error(404, 'not_found');
      if (!admitted) this.admit(ip);
      authTransaction(directory, expire);
      const digest = hash(typeof code === 'string' ? code : '');
      let c;
      authTransaction(directory, () => {
        const s = state(directory); c = s.codes.find((c) => timingSafeEqual(Buffer.from(c.code_hash, 'hex'), Buffer.from(digest, 'hex')));
        if (!c) return;
        let failure;
        try { limit(s.limits, `code:${digest}`, 10, anonymous); limit(s.limits, `claim:${c.tenant_id}:${c.hostname}`, 30, anonymous); } catch (e) { failure = e; }
        save(directory, s);
        if (failure) c = { failure };
      });
      if (c?.failure) throw c.failure;
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
          if (current.request_fingerprint !== fingerprint || current.key_fingerprint !== keyFingerprint) throw error(409, 'bootstrap_used');
          const credential = readJson('agent-credentials.json', [], directory).find((r) => r.id === current.credential_id);
          if (now() >= current.activate_by) throw error(410, 'bootstrap_expired');
          if (!current.response || !credential || credential.revoked_at) throw error(401, 'unauthorized');
        } else if (now() >= current.expires_at) throw error(410, 'bootstrap_expired');
      }
      classify(c);
      if (typeof opts.issuerCheck !== 'function') throw error(503, 'bootstrap_unavailable');
      let authorized;
      let timer;
      try { authorized = await Promise.race([opts.issuerCheck(structuredClone(c.issuer), { signal }), new Promise((_, reject) => {
        timer = setTimeout(() => reject(error(503, 'bootstrap_unavailable')), 5000);
      })]); } catch { throw error(503, 'bootstrap_unavailable'); } finally { clearTimeout(timer); }
      if (authorized === false) throw error(401, 'unauthorized');
      if (authorized !== true) throw error(503, 'bootstrap_unavailable');
      if (signal?.aborted) throw error(503, 'bootstrap_unavailable');
      // Recheck after the only asynchronous boundary, under the same synchronous writer lock.
      return authTransaction(directory, () => {
        expire(); const s = state(directory); c = s.codes.find((r) => r.code_hash === digest); classify(c);
        if (c.response) return c.response;
        const { token, record } = generateCredential({ tenant_id: c.tenant_id, hostname: c.hostname }, now);
        const activateBy = now() + 120000;
        Object.assign(record, { status: 'pending', key_fingerprint: keyFingerprint, activate_by: activateBy });
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
      service.admit(req.socket.remoteAddress);
      if (Number(req.headers['content-length']) > 16384) throw error(413, 'payload_too_large');
      const chunks = []; let size = 0;
      const body = await new Promise((resolve, reject) => {
        req.on('data', (chunk) => { size += chunk.length; if (size > 16384) { reject(error(413, 'payload_too_large')); return; } chunks.push(chunk); });
        req.on('error', () => reject(error(400, 'invalid_request')));
        abort.signal.addEventListener('abort', () => reject(error(503, 'bootstrap_unavailable')), { once: true });
        req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(error(400, 'invalid_request')); } });
      });
      const code = /^Bearer (fdab_[A-Za-z0-9_-]{43})$/.exec(req.headers.authorization ?? '')?.[1];
      send(200, await service.exchange(code, body, req.socket.remoteAddress, abort.signal, true));
    } catch (e) { const known = [400, 401, 409, 410, 413, 429, 503].includes(e.status); send(known ? e.status : 503, { error: known ? e.code : 'bootstrap_unavailable' }, e.retry_after); }
    finally { clearTimeout(timer); }
  };
}
