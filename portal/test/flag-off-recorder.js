// Records the portal's responses with agent bootstrap off (the default) for a fixed walk over existing pages and
// routes, masking per-run secrets and IDs. portal/test/flag-off-snapshot.test.js compares against the snapshot that
// was recorded from the pre-milestone-4 portal, so flag-off behaviour stays byte-for-byte unchanged.
// Script use: node portal/test/flag-off-recorder.js  (prints the JSON snapshot).
import { readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { fixture, request } from './helpers.js';

const host = 'app.example.test';
const mask = (text) => text
  .replace(/fd(?:ct|ak|ab)_[A-Za-z0-9_-]{43}/g, '<token>')
  .replace(/fake-[0-9a-f]{48}/g, '<fake>')
  .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, '<uuid>')
  .replace(/[0-9a-f]{32,}/g, '<hex>')
  .replace(/fdak_[A-Za-z0-9_-]{4}/g, '<prefix>')
  .replace(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z/g, '<time>');
const digest = (text) => createHash('sha256').update(mask(text)).digest('hex').slice(0, 16);

export async function record(t) {
  const f = await fixture(t, { edgeUrl: 'https://edge.example-edge.test', docsUrl: 'https://docs.example.test' });
  const out = [];
  const keep = (label, r) => out.push([mask(label),r.status, r.headers['content-type'] ?? null, r.headers.location ?? null, r.headers.allow ?? null, digest(r.text)]);
  const js = readdirSync(fileURLToPath(new URL('../public/js/', import.meta.url))).filter((n) => n.endsWith('.js') && n !== 'agent-bootstrap.js').sort();
  const pages = ['/', '/login', '/signup', '/hostname', '/verify-email', '/dashboard', '/start', '/connect', '/domains', '/plan', '/status', '/keys', '/agent', '/health', '/nope'];
  const statics = [...js.map((n) => `/js/${n}`), '/js/agent-bootstrap.js', '/css/site.css', '/css/portal.css', '/install/agent.sh', '/favicon.svg'];
  for (const path of [...pages, ...statics]) keep(`anon GET ${path}`, await request(f.port, path));
  const a = await f.seed();
  const call = async (label, path, method = 'GET', body, headers) => keep(`${label} ${method} ${path}`, await a.client.call(path, method, body, headers));
  for (const path of pages) await call('session', path);
  await call('session', '/api/me');
  await call('session', '/api/hostnames', 'POST', { hostname: host });
  await call('session', `/api/hostnames/${host}/connect-token`, 'POST');
  await call('session', `/api/hostnames/${host}/verify`, 'POST');
  await call('session', '/api/hostnames');
  await call('session', `/api/hostnames/${host}`);
  for (const suffix of ['bootstraps', 'revoke-agent', 'bootstraps/candidates/x/confirm', 'unknown']) {
    for (const method of ['GET', 'POST', 'DELETE']) await call('session', `/api/hostnames/${host}/${suffix}`, method, method === 'GET' ? undefined : { origin: 'http://127.0.0.1:3000', confirm: true });
  }
  const issued = await a.client.call(`/api/hostnames/${host}/connect-token`, 'POST');
  keep('session POST connect-token (active)', issued);
  await call('session', `/api/hostnames/${host}/connect-token`);
  const key = await a.client.call('/api/keys', 'POST', { password: a.password, scopes: ['connect', 'status:read', 'hostnames:create'] });
  keep('session POST /api/keys', key);
  await call('session', '/api/keys');
  const bearer = (secret) => ({ authorization: `Bearer ${secret}`, 'content-type': 'application/json' });
  const viaKey = async (method, path, body) => keep(`key ${method} ${path}`, await request(f.port, path, { method, headers: bearer(key.data.key), body }));
  await viaKey('GET', `/api/v1/hostnames/${host}`);
  await viaKey('GET', `/api/v1/hostnames/${host}/status`);
  await viaKey('POST', `/api/v1/hostnames/${host}/bootstraps`, { origin: 'http://127.0.0.1:3000' });
  await viaKey('GET', `/api/v1/hostnames/${host}/bootstraps`);
  await viaKey('POST', `/api/v1/hostnames/${host}/connect`, { origin: 'http://127.0.0.1:3000', platform: 'docker', format: 'env' });
  await viaKey('POST', `/api/v1/hostnames/${host}/connect`, { origin: 'http://127.0.0.1:3000', platform: 'docker' });
  const viaToken = async (method, path, body) => keep(`token ${method} ${path}`, await request(f.port, path, { method, headers: bearer(issued.data.token), body }));
  await viaToken('GET', '/api/connect/v1/hostname');
  await viaToken('POST', '/api/connect/v1/bootstrap', { origin: 'http://127.0.0.1:3000' });
  await viaToken('GET', '/api/connect/v1/bootstrap');
  await viaToken('POST', '/api/connect/v1/command', { origin: 'http://127.0.0.1:3000', platform: 'docker', format: 'env' });
  await viaToken('POST', '/api/connect/v1/command', { origin: 'http://127.0.0.1:3000', platform: 'docker', format: 'env' });
  await call('session', `/api/hostnames/${host}/connect-token`, 'DELETE');
  await call('session', `/api/hostnames/${host}/rotate`, 'POST');
  await call('session', `/api/keys/${key.data.id}`, 'DELETE');
  await call('session', `/api/hostnames/${host}`, 'DELETE');
  return out;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const cleanups = [];
  const out = await record({ after: (fn) => cleanups.push(fn) });
  process.stdout.write(`${JSON.stringify(out, null, 1)}\n`);
  for (const fn of cleanups.reverse()) await fn();
}
