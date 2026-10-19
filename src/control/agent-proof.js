import { createHash, createPublicKey, verify, constants } from 'node:crypto';
import { equalHash } from './auth.js';

// Key-bound agent request proof (bootstrap milestone 2). Legacy bearer credentials never reach this module.
export const PROOF_HEADER = 'x-fastdog-agent-proof';
export const PROOF_LABEL = 'fastdog-agent-proof-v1';
export const PROOF_SKEW_MS = 60000;
const MAX_DECODED = 2048;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export function lengthPrefixed(values) {
  return Buffer.concat(values.map((value) => {
    const bytes = Buffer.from(value); const size = Buffer.alloc(4); size.writeUInt32BE(bytes.length); return Buffer.concat([size, bytes]);
  }));
}

export function proofTranscript({ method, target, audience, credentialId, timestamp, nonce, body }) {
  return lengthPrefixed([PROOF_LABEL, method, target, audience, credentialId, String(timestamp), nonce, sha256(body ?? Buffer.alloc(0))]);
}

// Strict base64url: the canonical re-encoding must equal the input.
function base64url(value, bytes) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.toString('base64url') === value && (bytes === undefined || decoded.length === bytes) ? decoded : null;
}

// Exactly one header whose decoded JSON is the canonical {v,nonce,timestamp,signature} serialization.
export function parseProof(values) {
  if (!Array.isArray(values) || values.length !== 1 || typeof values[0] !== 'string' || values[0].length > Math.ceil(MAX_DECODED / 3) * 4) return null;
  const decoded = base64url(values[0]);
  if (!decoded || decoded.length > MAX_DECODED) return null;
  let proof;
  try { proof = JSON.parse(decoded.toString('utf8')); } catch { return null; }
  if (!proof || typeof proof !== 'object' || Array.isArray(proof) || proof.v !== 1 || !Number.isSafeInteger(proof.timestamp) ||
    !base64url(proof.nonce, 32) || !base64url(proof.signature, 384)) return null;
  const { v, nonce, timestamp, signature } = proof;
  return JSON.stringify({ v, nonce, timestamp, signature }) === decoded.toString('utf8') ? proof : null;
}

export function proofHeaderValues(req) {
  const values = []; const raw = req.rawHeaders ?? [];
  for (let i = 0; i + 1 < raw.length; i += 2) if (String(raw[i]).toLowerCase() === PROOF_HEADER) values.push(raw[i + 1]);
  return values;
}

// Request facts the proof is checked against. Disabled bootstrap yields no context, so key-bound auth fails closed.
export function agentAuthContext(req, { enabled, audience, body } = {}) {
  if (!enabled) return {};
  const query = new URLSearchParams(String(req.url ?? '').split('?')[1] ?? '');
  return { candidate: query.get('candidate') === '1',
    proof: { values: proofHeaderValues(req), method: req.method, target: req.originalUrl ?? req.url, audience, body: body ?? Buffer.alloc(0) } };
}

export function createNonceCache({ perCredential = 128, global = 20000 } = {}) {
  const table = new Map(); let size = 0; let swept = -Infinity;
  function prune(id, entries, time) {
    for (const [nonce, until] of entries) if (until <= time) { entries.delete(nonce); size--; }
    if (!entries.size) table.delete(id);
  }
  return {
    get size() { return size; },
    consume(id, nonce, until, time) {
      if (table.has(id)) prune(id, table.get(id), time);
      // At global capacity, at most one full sweep per second; still full means fail closed, never evict live nonces.
      if (size >= global && time - swept >= 1000) { swept = time; for (const [key, entries] of table) prune(key, entries, time); }
      const entries = table.get(id);
      if (entries?.has(nonce) || (entries?.size ?? 0) >= perCredential || size >= global) return false;
      if (entries) entries.set(nonce, until); else table.set(id, new Map([[nonce, until]]));
      size++;
      return true;
    },
    clear() { table.clear(); size = 0; swept = -Infinity; },
  };
}
export const agentNonces = createNonceCache();

// True only for a fresh, unreplayed signature by exactly the record's bound key. Consumes the nonce on success.
export function verifyAgentProof(context, record, now = Date.now, nonces = agentNonces) {
  if (!context || typeof context.audience !== 'string' || !context.audience || typeof record?.public_key !== 'string' || typeof record.id !== 'string') return false;
  const proof = parseProof(context.values);
  if (!proof) return false;
  const time = now();
  if (Math.abs(time - proof.timestamp * 1000) > PROOF_SKEW_MS) return false;
  let key;
  try {
    key = createPublicKey({ key: Buffer.from(record.public_key, 'base64'), format: 'der', type: 'spki' });
    if (!equalHash(sha256(key.export({ type: 'spki', format: 'der' })), record.key_fingerprint)) return false;
  } catch { return false; }
  const transcript = proofTranscript({ method: context.method, target: context.target, audience: context.audience,
    credentialId: record.id, timestamp: proof.timestamp, nonce: proof.nonce, body: context.body });
  let valid = false;
  try { valid = verify('sha256', transcript, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, Buffer.from(proof.signature, 'base64url')); } catch { return false; }
  return valid && nonces.consume(record.id, proof.nonce, proof.timestamp * 1000 + PROOF_SKEW_MS, time);
}
