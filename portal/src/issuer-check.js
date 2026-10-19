// Portal-internal issuer check (agent bootstrap; only with PORTAL_AGENT_BOOTSTRAP_ENABLED=1 and a configured
// PORTAL_ISSUER_CHECK_KEY). A separate loopback-only listener with one route: the edge asks whether an issuer (kind,
// ID, authorization generation) is still eligible, with a fresh 32-byte nonce, authenticated by an HMAC under a key
// derived from the per-environment service secret. The reply echoes only those fields plus `valid` and `checked_at`,
// with an HMAC under a distinct reply-direction key. The encoding must match src/onboard/issuer-check.js byte for byte.
// No other portal route knows this credential, so it authenticates nothing anywhere else.
import http from 'node:http';
import { isIP } from 'node:net';
import { createHmac, hkdfSync, timingSafeEqual, createHash } from 'node:crypto';

export const ISSUER_CHECK_PATH = '/internal/v1/issuer-check';
export const MAC_HEADER = 'x-fastdog-issuer-mac';
export const ISSUER_KINDS = Object.freeze(['session', 'api_key', 'connect_token']);
const LABEL = 'fastdog-issuer-check-v1';
const REQUEST_FIELDS = ['issuer_kind', 'issuer_id', 'authorization_generation', 'nonce'];

export function lengthPrefixed(values) {
  return Buffer.concat(values.map((value) => {
    const bytes = Buffer.from(value); const size = Buffer.alloc(4); size.writeUInt32BE(bytes.length); return Buffer.concat([size, bytes]);
  }));
}
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

const loopback = (address) => address === '::1' || (isIP(address) === 4 && address.startsWith('127.')) ||
  (address?.startsWith('::ffff:') && isIP(address.slice(7)) === 4 && address.slice(7).startsWith('127.'));
const forwarded = (headers) => Object.keys(headers).some((name) => ['forwarded', 'x-real-ip', 'via', 'cf-connecting-ip'].includes(name) || name.startsWith('x-forwarded-'));
const text = (value) => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const nonce = (value) => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value;

// Fixed-window counters: one bucket per service key plus one global bucket, so the table is bounded by construction.
function createLimiter(now) {
  const buckets = new Map();
  return (key, limit) => {
    const time = now();
    let bucket = buckets.get(key);
    if (!bucket || bucket.reset <= time) { if (!bucket && buckets.size >= 16) buckets.clear(); bucket = { count: 0, reset: time + 60000 }; buckets.set(key, bucket); }
    if (bucket.count >= limit) return Math.max(1, Math.ceil((bucket.reset - time) / 1000));
    bucket.count++;
    return 0;
  };
}

// `validate({ issuer_kind, issuer_id, authorization_generation })` returns a boolean (unknown, revoked and expired are all
// false); a throw means the portal cannot answer (503), never a false "valid".
// `limits` is a test seam only (one environment has one key, so the global bucket is otherwise unreachable in tests).
export function createIssuerCheckServer({ secret, validate, now = Date.now, logger, limits = { perKey: 60, global: 300 } } = {}) {
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('Issuer check key must contain at least 32 characters');
  const keys = issuerCheckKeys(secret);
  const keyId = createHash('sha256').update(keys.request).digest('hex').slice(0, 16);
  const limited = createLimiter(now);
  const server = http.createServer({ requestTimeout: 5000, headersTimeout: 5000 }, (request, response) => {
    const send = (status, data, headers = {}) => {
      if (response.headersSent) return;
      response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
      response.end(data === undefined ? '' : JSON.stringify(data));
    };
    // Status codes only: never the issuer, nonce, MAC or key.
    response.on('finish', () => { try { logger?.({ route: 'issuer-check', status: response.statusCode }); } catch { /* Logging cannot affect a response. */ } });
    // Loopback peers only, never through a proxy: a forwarded request is indistinguishable from an external one.
    if (!loopback(request.socket.remoteAddress) || forwarded(request.headers)) return send(404, { error: 'not_found' });
    if (request.url !== ISSUER_CHECK_PATH) return send(404, { error: 'not_found' });
    if (request.method !== 'POST') return send(405, { error: 'method_not_allowed' }, { Allow: 'POST' });
    const chunks = []; let size = 0;
    request.on('data', (chunk) => { size += chunk.length; if (size <= 1024) chunks.push(chunk); });
    request.on('error', () => send(400, { error: 'invalid_json' }));
    request.on('end', () => {
      if (size > 1024) return send(413, { error: 'payload_too_large' });
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return send(400, { error: 'invalid_json' }); }
      if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).length !== REQUEST_FIELDS.length || !REQUEST_FIELDS.every((k) => Object.hasOwn(body, k)) ||
        !text(body.issuer_kind) || !text(body.issuer_id) || !nonce(body.nonce) ||
        !(text(body.authorization_generation) || (Number.isSafeInteger(body.authorization_generation) && body.authorization_generation >= 0))) return send(400, { error: 'invalid_json' });
      if (!macMatches(issuerMac(keys.request, requestEncoding(body)), request.headers[MAC_HEADER])) return send(401, { error: 'unauthorized' });
      // Narrow bucket first, so a limited key never consumes global capacity.
      const retry = limited(`key:${keyId}`, limits.perKey) || limited('global', limits.global);
      if (retry) return send(429, { error: 'rate_limited', retry_after: retry }, { 'Retry-After': String(retry) });
      let valid;
      try { valid = ISSUER_KINDS.includes(body.issuer_kind) && validate({ ...body }) === true; } catch { return send(503, { error: 'unavailable' }); }
      const reply = { issuer_kind: body.issuer_kind, issuer_id: body.issuer_id, authorization_generation: body.authorization_generation, nonce: body.nonce, valid, checked_at: now() };
      send(200, reply, { [MAC_HEADER]: issuerMac(keys.reply, replyEncoding(reply)) });
    });
  });
  server.setTimeout(5000);
  return server;
}
