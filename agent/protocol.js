// Bootstrap and proof wire formats (must match src/onboard/bootstrap.js and src/control/agent-proof.js byte for byte)
// plus the strict edge transport: verified TLS with the image's bundled roots, no redirects, bounded responses.
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { createHash, generateKeyPairSync, randomBytes, sign, privateDecrypt, constants } from 'node:crypto';

export const EXCHANGE_PATH = '/_fastdog/agents/bootstrap/exchange';
export const REGISTER_PATH = '/_fastdog/agents/register';
export const PROOF_HEADER = 'X-Fastdog-Agent-Proof';
export const OAEP_LABEL = Buffer.from('fastdog-agent-bootstrap-v1');
const EXCHANGE_FIELDS = ['hostname', 'origin', 'deployment_id', 'request_id', 'recipient_public_key', 'agent_version'];
const MAX_RESPONSE = 65536;
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export function lengthPrefixed(values) {
  return Buffer.concat(values.map((value) => {
    const bytes = Buffer.from(value); const size = Buffer.alloc(4); size.writeUInt32BE(bytes.length); return Buffer.concat([size, bytes]);
  }));
}

export const exchangeTranscript = (audience, digest, body) =>
  lengthPrefixed(['fastdog-agent-bootstrap-v1', 'POST', EXCHANGE_PATH, audience, digest, ...EXCHANGE_FIELDS.map((k) => body[k])]);

export const proofTranscript = ({ method, target, audience, credentialId, timestamp, nonce, body }) =>
  lengthPrefixed(['fastdog-agent-proof-v1', method, target, audience, credentialId, String(timestamp), nonce, sha256(body ?? Buffer.alloc(0))]);

const pss = (privateKey) => ({ key: privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });

export function generateKey() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 3072, publicExponent: 65537 });
  return {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
    fingerprint: sha256(publicKey.export({ type: 'spki', format: 'der' })),
  };
}

export function signExchange(privateKey, audience, digest, body) {
  return sign('sha256', exchangeTranscript(audience, digest, body), pss(privateKey)).toString('base64url');
}

// Fresh nonce and timestamp per request; canonical {v,nonce,timestamp,signature} JSON, base64url encoded.
export function proofHeader(privateKey, { method, target, audience, credentialId, body, now = Date.now }) {
  const timestamp = Math.floor(now() / 1000), nonce = randomBytes(32).toString('base64url');
  const signature = sign('sha256', proofTranscript({ method, target, audience, credentialId, timestamp, nonce, body }), pss(privateKey)).toString('base64url');
  return Buffer.from(JSON.stringify({ v: 1, nonce, timestamp, signature })).toString('base64url');
}

export function decryptToken(privateKey, ciphertext) {
  const token = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256', oaepLabel: OAEP_LABEL },
    Buffer.from(ciphertext, 'base64url')).toString('utf8');
  if (!/^[0-9a-f]{64}$/.test(token)) throw new Error('invalid_token');
  return token;
}

const LOOPBACK = ['127.0.0.1', '::1', '[::1]', 'localhost'];
// Resolves the address actually dialled. Production: the pinned https/wss URL itself. Injected test fixtures may
// substitute a loopback http/ws base for the same path; the environment can never select this.
export function dialTarget(pinnedUrl, fixtureBase) {
  const pinned = new URL(pinnedUrl);
  if (!fixtureBase) {
    if (!['https:', 'wss:'].includes(pinned.protocol)) throw new Error('insecure_edge');
    return { url: pinned, secure: true };
  }
  const base = new URL(fixtureBase);
  if (!LOOPBACK.includes(base.hostname) || !['http:', 'ws:'].includes(base.protocol)) throw new Error('fixture_not_loopback');
  return { url: new URL(`${base.protocol}//${base.host}${pinned.pathname}${pinned.search}`), secure: false };
}

// Mandatory verification against the bundled roots: NODE_TLS_REJECT_UNAUTHORIZED and NODE_EXTRA_CA_CERTS cannot relax it.
export const tlsOptions = () => ({ rejectUnauthorized: true, ca: tls.rootCertificates });

export function edgeRequest(pinnedUrl, { method = 'POST', headers = {}, body, fixture, timeoutMs = 15000 } = {}) {
  const { url, secure } = dialTarget(pinnedUrl, fixture);
  const pinned = new URL(pinnedUrl);
  return new Promise((resolve, reject) => {
    const req = (secure ? https : http).request({
      protocol: url.protocol, hostname: url.hostname.replace(/^\[|\]$/g, ''), port: url.port || (secure ? 443 : 80), path: `${url.pathname}${url.search}`,
      method, agent: false, timeout: timeoutMs,
      headers: { ...headers, host: pinned.host, ...(body ? { 'content-length': String(body.length) } : {}) },
      ...(secure ? { ...tlsOptions(), servername: pinned.hostname } : {}),
    }, (res) => {
      const chunks = []; let size = 0;
      res.on('data', (chunk) => { size += chunk.length; if (size > MAX_RESPONSE) { req.destroy(new Error('response_too_large')); return; } chunks.push(chunk); });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('edge_timeout')));
    req.on('error', reject);
    req.end(body);
  });
}
