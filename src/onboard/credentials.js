import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { readJson, writeJson, dataDir, authTransaction, combined } from './json.js';
import { normalizeHostname } from './hostname.js';

// At most one persisted last_used_at update per credential per window.
export const LAST_USED_WRITE_INTERVAL = 60000;

export function tenantOwner(hostname, directory = dataDir()) {
  let host;
  try { host = normalizeHostname(hostname); } catch { return undefined; }
  return readJson('tenant_hostnames.json', [], directory).find((claim) => claim.hostname === host && claim.status === 'active');
}

export function issueCredential(input = {}, directory = dataDir(), now = Date.now) {
  return authTransaction(directory, () => issueCredentialRecord(input, directory, now));
}
function issueCredentialRecord({ name, hostname, tenant_id }, directory, now) {
  let host;
  if (hostname) {
    if (tenant_id) host = normalizeHostname(hostname);
    else {
      host = String(hostname).replace(/\.$/, '').toLowerCase();
      if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) {
        throw Object.assign(new Error('invalid_domain'), { status: 400 });
      }
    }
  }
  const { token, record } = generateCredential({ name, hostname: host, tenant_id }, now);
  const id = record.id;
  const credentials = readJson('agent-credentials.json', [], directory);
  credentials.push(record);
  writeJson('agent-credentials.json', credentials, 0o600, directory);
  return { id, token, agent_env: { AGENT_TOKEN: token, ...(name ? { AGENT_NAME: name } : {}), ...(host ? { AGENT_HOSTNAME: host } : {}) } };
}

export function validCredential(token, hostname, directory = dataDir(), now = Date.now) {
  return authTransaction(directory, () => validateCredential(token, hostname, directory, now));
}
function validateCredential(token, hostname, directory, now) {
  if (combined(directory)) authTransaction(directory, () => {
    const records = readJson('agent-credentials.json', [], directory);
    let changed = false;
    for (const c of records) if (c.status === 'pending' && !c.revoked_at && now() >= c.activate_by) { c.revoked_at = new Date(now()).toISOString(); changed = true; }
    if (changed) writeJson('agent-credentials.json', records, 0o600, directory);
  });
  if (typeof token !== 'string' || !token) return false;
  let host = String(hostname).toLowerCase();
  try { host = normalizeHostname(hostname); } catch { /* Preserve legacy host matching. */ }
  const owner = tenantOwner(host, directory);
  const hash = createHash('sha256').update(token).digest();
  const credentials = readJson('agent-credentials.json', [], directory);
  const credential = credentials.find((item) => {
    if (item.key_fingerprint !== undefined || ['pending', 'held'].includes(item.status) || item.revoked_at || (item.hostname && item.hostname !== host)) return false;
    if (owner && (item.tenant_id !== owner.tenant_id || item.claim_hostname !== host || item.id !== owner.credential_id)) return false;
    if (item.tenant_id && (!owner || owner.tenant_id !== item.tenant_id)) return false;
    const stored = Buffer.from(item.token_hash || '', 'hex');
    return stored.length === hash.length && timingSafeEqual(stored, hash);
  });
  if (!credential) return false;
  if (combined(directory)) return true;
  // The decision above always uses a fresh read; only the last_used_at write is throttled.
  const time = now();
  const last = Date.parse(credential.last_used_at);
  if (time >= last && time - last < LAST_USED_WRITE_INTERVAL) return true;
  credential.last_used_at = new Date(time).toISOString();
  writeJson('agent-credentials.json', credentials, 0o600, directory);
  return true;
}

export function generateCredential({ name, hostname: host, tenant_id } = {}, now = Date.now) {
  const token = randomBytes(32).toString('hex');
  return { token, record: { id: randomUUID(), name: name || undefined, hostname: host,
    token_hash: createHash('sha256').update(token).digest('hex'), created_at: new Date(now()).toISOString(),
    tenant_id: tenant_id || null, claim_hostname: tenant_id ? host : null, revoked_at: null, last_used_at: null } };
}
