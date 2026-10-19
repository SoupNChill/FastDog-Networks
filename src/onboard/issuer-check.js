// Authenticated issuer-check client (bootstrap plan section 4). The edge asks the portal's loopback-only issuer-check
// listener whether an issuer (kind, ID, authorization generation) is still eligible. Requests carry an HMAC under the
// request-direction key; replies must carry an HMAC under the distinct reply-direction key, echo the outstanding request
// exactly, use its fresh single-use nonce and be timestamped within 5 seconds. Anything else is unavailable (503),
// never valid. The encoding must match portal/src/issuer-check.js byte for byte.
import http from 'node:http';
import { randomBytes, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';
import { lengthPrefixed } from '../control/agent-proof.js';

export const ISSUER_CHECK_PATH = '/internal/v1/issuer-check';
export const MAC_HEADER = 'x-fastdog-issuer-mac';
export const REPLY_WINDOW_MS = 5000;
const LABEL = 'fastdog-issuer-check-v1';
const REPLY_FIELDS = ['issuer_kind', 'issuer_id', 'authorization_generation', 'nonce', 'valid', 'checked_at'];
const MAX_REPLY = 4096;

// Bounded rejection counters: fixed reason labels only, never hostnames, tenants, issuers or nonces.
export const REJECT_REASONS = Object.freeze(['capacity', 'transport', 'status', 'rate_limited', 'malformed', 'missing_mac', 'invalid_mac',
  'unknown_nonce', 'reused_nonce', 'expired_nonce', 'different_request', 'mismatch', 'stale']);
const rejected = Object.fromEntries(REJECT_REASONS.map((reason) => [reason, 0]));
export const issuerReplyRejected = () => ({ ...rejected });

export function issuerCheckKeys(secret) {
  const derive = (info) => Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.from(LABEL), Buffer.from(info), 32));
  return { request: derive('fastdog-issuer-check-request-v1'), reply: derive('fastdog-issuer-check-reply-v1') };
}
export const requestEncoding = (r) => lengthPrefixed([LABEL, 'request', r.issuer_kind, r.issuer_id, JSON.stringify(r.authorization_generation), r.nonce]);
export const replyEncoding = (r) => lengthPrefixed([LABEL, 'reply', r.issuer_kind, r.issuer_id, JSON.stringify(r.authorization_generation), r.nonce,
  r.valid === true ? 'true' : 'false', String(r.checked_at)]);
export const issuerMac = (key, bytes) => createHmac('sha256', key).update(bytes).digest('base64url');
export function macMatches(expected, given) {
  if (typeof given !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(given)) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(given));
}

const loopbackUrl = (value) => {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname) && url.pathname === ISSUER_CHECK_PATH &&
      !url.search && !url.hash && !url.username && !url.password ? url : null;
  } catch { return null; }
};

function post(url, body, headers, { signal, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method: 'POST', agent: false, timeout: timeoutMs, signal,
      headers: { ...headers, 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (res) => {
      const chunks = []; let size = 0;
      res.on('data', (chunk) => { size += chunk.length; if (size > MAX_REPLY) req.destroy(new Error('reply_too_large')); else chunks.push(chunk); });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    const deadline = setTimeout(() => req.destroy(new Error('issuer_check_timeout')), timeoutMs);
    req.on('close', () => clearTimeout(deadline));
    req.on('timeout', () => req.destroy(new Error('issuer_check_timeout')));
    req.on('error', reject);
    req.end(body);
  });
}

// `transport` is a test seam (same contract as post). Returns { check, begin, accept }.
export function createIssuerChecker({ url, secret, now = Date.now, timeoutMs = REPLY_WINDOW_MS, capacity = 1024, transport = post } = {}) {
  const target = loopbackUrl(url);
  if (!target || typeof secret !== 'string' || secret.length < 32) throw new Error('issuer check configuration is invalid');
  const keys = issuerCheckKeys(secret);
  // Outstanding nonces: discarded 5 s after issue, kept one more window as used/expired markers, bounded.
  const nonces = new Map();
  const reject = (reason) => { rejected[reason]++; return Object.assign(new Error('bootstrap_unavailable'), { status: 503, code: 'bootstrap_unavailable', reason }); };
  function sweep() {
    const time = now();
    for (const [nonce, entry] of nonces) { if (entry.expires + REPLY_WINDOW_MS > time) break; nonces.delete(nonce); }
  }
  function begin(issuer) {
    sweep();
    if (nonces.size >= capacity) throw reject('capacity');
    const request = { issuer_kind: issuer?.kind, issuer_id: issuer?.id, authorization_generation: issuer?.authorization_generation, nonce: randomBytes(32).toString('base64url') };
    nonces.set(request.nonce, { request, expires: now() + REPLY_WINDOW_MS, used: false });
    return request;
  }
  // Accepts a reply for exactly this outstanding request; returns its boolean or throws a 503 with a bounded reason.
  function accept(request, res) {
    const own = nonces.get(request.nonce);
    try {
      if (res.status === 429) throw reject('rate_limited');
      if (res.status !== 200) throw reject('status');
      let reply;
      try { reply = JSON.parse(Buffer.from(res.body).toString('utf8')); } catch { throw reject('malformed'); }
      if (!reply || typeof reply !== 'object' || Array.isArray(reply) || Object.keys(reply).length !== REPLY_FIELDS.length || !REPLY_FIELDS.every((k) => Object.hasOwn(reply, k)) ||
        typeof reply.issuer_kind !== 'string' || typeof reply.issuer_id !== 'string' || typeof reply.nonce !== 'string' ||
        !['string', 'number'].includes(typeof reply.authorization_generation) || typeof reply.valid !== 'boolean' || !Number.isSafeInteger(reply.checked_at)) throw reject('malformed');
      const given = res.headers?.[MAC_HEADER];
      if (given === undefined || given === '') throw reject('missing_mac');
      if (!macMatches(issuerMac(keys.reply, replyEncoding(reply)), given)) throw reject('invalid_mac');
      const entry = nonces.get(reply.nonce);
      if (!entry) throw reject('unknown_nonce');
      if (entry.used) throw reject('reused_nonce');
      if (now() > entry.expires) throw reject('expired_nonce');
      if (entry !== own) throw reject('different_request');
      if (reply.issuer_kind !== request.issuer_kind || reply.issuer_id !== request.issuer_id || reply.authorization_generation !== request.authorization_generation) throw reject('mismatch');
      if (Math.abs(now() - reply.checked_at) > REPLY_WINDOW_MS) throw reject('stale');
      return reply.valid;
    } finally { if (own) own.used = true; }
  }
  async function check(issuer, { signal } = {}) {
    const request = begin(issuer);
    let res;
    try {
      res = await transport(target, JSON.stringify(request), { [MAC_HEADER]: issuerMac(keys.request, requestEncoding(request)) }, { signal, timeoutMs });
    } catch {
      const entry = nonces.get(request.nonce); if (entry) entry.used = true;
      throw reject('transport');
    }
    return accept(request, res);
  }
  return { check, begin, accept };
}

// Production wiring: both settings unset means no checker (bootstrap fails closed with 503). A partial or invalid
// configuration, or a key reused from another credential, fails enabled startup. Messages never contain values.
export function issuerCheckFromEnv(env = process.env, opts = {}) {
  const url = env.AGENT_BOOTSTRAP_ISSUER_CHECK_URL, secret = env.AGENT_BOOTSTRAP_ISSUER_CHECK_KEY;
  if (!url && !secret) return undefined;
  if (!url || !secret || secret.length < 32 || [env.PORTAL_KEY, env.AGENT_TOKEN].includes(secret)) {
    throw new Error('AGENT_BOOTSTRAP_ISSUER_CHECK_URL and AGENT_BOOTSTRAP_ISSUER_CHECK_KEY must both be set; the key needs 32+ characters and must differ from PORTAL_KEY and AGENT_TOKEN');
  }
  return createIssuerChecker({ url, secret, ...opts }).check;
}
