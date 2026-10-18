import { createHash, timingSafeEqual } from 'node:crypto';
import { readJson, writeJson, authTransaction, dataDir } from './json.js';
import { tenantOwner, candidateExpired, expireCandidates } from './credentials.js';
import { normalizeHostname } from './hostname.js';
import { equalHash } from '../control/auth.js';
import { verifyAgentProof } from '../control/agent-proof.js';

// Bootstrap milestone 2: candidate (unpromoted, key-bound) credentials. Never consulted by active authentication.
const CREDENTIALS = 'agent-credentials.json';
const live = (c, time) => c && c.key_fingerprint !== undefined && ['pending', 'held'].includes(c.status) && !c.revoked_at && !candidateExpired(c, time);

function expire(directory, time) {
  const records = readJson(CREDENTIALS, [], directory);
  if (expireCandidates(records, time)) writeJson(CREDENTIALS, records, 0o600, directory);
  return records;
}

// The issuing code must still match the current active ownership and selected credential generations.
function bound(record, owner, directory) {
  if (!owner || owner.tenant_id !== record.tenant_id || owner.hostname !== record.claim_hostname || owner.credential_id === record.id) return false;
  const code = readJson('agent-bootstrap.json', {}, directory).codes?.find((c) => c.credential_id === record.id);
  return Boolean(code && !code.cancelled && code.tenant_id === owner.tenant_id && code.hostname === owner.hostname &&
    code.claim_generation === owner.created_at && code.credential_generation === owner.credential_id);
}

// Read-only apart from deadline revocation: returns the candidate record or null. Never falls back to active auth.
export function validCandidateCredential(token, hostname, directory = dataDir(), now = Date.now, proof = undefined) {
  return authTransaction(directory, () => {
    const time = now(); const records = expire(directory, time);
    if (typeof token !== 'string' || !token) return null;
    let host;
    try { host = normalizeHostname(hostname); } catch { return null; }
    const owner = tenantOwner(host, directory);
    const hash = createHash('sha256').update(token).digest();
    const record = records.find((c) => {
      const stored = Buffer.from(c.token_hash || '', 'hex');
      return stored.length === hash.length && timingSafeEqual(stored, hash);
    });
    if (!live(record, time) || record.claim_hostname !== host || !bound(record, owner, directory)) return null;
    return verifyAgentProof(proof, record, now) ? record : null;
  });
}

// Durable liveness by ID, for sweeps of candidates that are not ready.
export function candidateLive(directory = dataDir(), id, now = Date.now) {
  return authTransaction(directory, () => {
    const time = now(); const record = expire(directory, time).find((c) => c.id === id);
    return live(record, time) && bound(record, tenantOwner(record.claim_hostname, directory), directory);
  });
}

// One transaction: hold, or select the candidate and revoke every other credential for the claim.
// `activeConnected`/`absentLongEnough` come from the registry in the same synchronous turn.
export function promoteCandidate(directory = dataDir(), id, now = Date.now, { activeConnected, absentLongEnough, confirmed = false, keyFingerprint } = {}) {
  return authTransaction(directory, () => {
    const time = now(); const records = expire(directory, time);
    const record = records.find((c) => c.id === id);
    if (!live(record, time)) return { state: 'invalid' };
    const claims = readJson('tenant_hostnames.json', [], directory);
    const owner = claims.find((c) => c.hostname === record.claim_hostname && c.status === 'active');
    if (!bound(record, owner, directory)) return { state: 'invalid' };
    if (confirmed && (record.status !== 'held' || !equalHash(keyFingerprint, record.key_fingerprint))) return { state: 'mismatch' };
    const current = records.find((c) => c.id === owner.credential_id && !c.revoked_at);
    if (!confirmed && (activeConnected || (current && !absentLongEnough))) {
      if (record.status !== 'held') { record.status = 'held'; record.held_at = new Date(time).toISOString(); writeJson(CREDENTIALS, records, 0o600, directory); }
      return { state: 'held' };
    }
    const stamp = new Date(time).toISOString();
    for (const c of records) if (c !== record && c.tenant_id === record.tenant_id && c.claim_hostname === record.claim_hostname && !c.revoked_at) c.revoked_at = stamp;
    Object.assign(record, { status: 'active', promoted_at: stamp });
    owner.credential_id = record.id;
    writeJson(CREDENTIALS, records, 0o600, directory);
    writeJson('tenant_hostnames.json', claims, 0o600, directory);
    return { state: 'promoted', replaced: current?.id ?? null };
  });
}
