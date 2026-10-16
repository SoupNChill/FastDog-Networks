import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { isIP } from 'node:net';
import { createStore } from './store.js';
import { createSessions } from './sessions.js';
import { createRateLimits } from './rate-limits.js';
import { createAuth } from './auth.js';
import { equal } from './tokens.js';
import { fail, statuses } from './errors.js';
import { normalizeHostname } from './hostname.js';
import { safePath, serveStatic, pages } from './static.js';
import { createFileMailer } from './mailer-file.js';

const authPaths = new Set(['/api/signup', '/api/login', '/api/logout', '/api/verify-email', '/api/password-reset', '/api/password-reset/confirm']);
const staticRoutes = new Map([
  ...[...authPaths].map((path) => [path, ['POST']]),
  ['/api/me', ['GET']], ['/api/hostnames', ['GET', 'POST']], ['/api/domains/search', ['GET']],
  ['/api/domain-requests', ['GET', 'POST']], ['/api/plan', ['GET']],
]);
const pick = (value, keys) => Object.fromEntries(keys.filter((key) => value?.[key] !== undefined).map((key) => [key, value[key]]));
function hostnameRecord(record) {
  const result = pick(record, ['hostname', 'status', 'created_at', 'expires_at', 'verified_at']);
  if (record.status === 'pending' && record.dns) result.dns = record.dns;
  if (record.agent) result.agent = pick(record.agent, ['connected', 'last_seen', 'registered_at']);
  return result;
}
async function readBody(request) {
  const parts = [];
  let size = 0;
  const timeout = setTimeout(() => request.destroy(), 5000);
  try {
    for await (const part of request) {
      size += part.length;
      if (size > 16384) throw fail('payload_too_large');
      parts.push(part);
    }
    const value = size ? JSON.parse(Buffer.concat(parts).toString('utf8')) : {};
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw fail('invalid_json');
    return value;
  } catch (error) { throw error.code === 'payload_too_large' ? error : fail('invalid_json'); }
  finally { clearTimeout(timeout); }
}
function clientIp(request, trustProxy) {
  const remote = request.socket.remoteAddress || 'unknown';
  const forwarded = request.headers['x-forwarded-for'];
  if (trustProxy && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(remote) && typeof forwarded === 'string') {
    const ip = forwarded.trim();
    if (isIP(ip)) return ip;
  }
  return remote;
}
export function createApp({ dataDir, edge, mailer, domainSearch, now = Date.now, config = {} } = {}) {
  config = { defaultPlan: 'assigned', defaultHostnameLimit: 3, ...config,
    origin: config.origin || config.portalOrigin || 'https://portal.example.test' };
  const origin = new URL(config.origin);
  if (origin.protocol !== 'https:' || origin.origin !== config.origin) throw new Error('HTTPS portal origin required');
  if (!Number.isInteger(config.defaultHostnameLimit) || config.defaultHostnameLimit < 1 || config.defaultHostnameLimit > 1000
    || typeof config.defaultPlan !== 'string' || !config.defaultPlan.trim()) throw new Error('Invalid default plan');
  // Public edge address agents dial (PORTAL_EDGE_URL). Without it the portal never renders a connect command.
  const edgeUrl = config.edgeUrl ? String(config.edgeUrl).replace(/\/$/, '') : null;
  if (edgeUrl) {
    let parsedEdge;
    try { parsedEdge = new URL(edgeUrl); } catch { throw new Error('Invalid public edge URL'); }
    if (parsedEdge.protocol !== 'https:' || parsedEdge.origin !== edgeUrl || !/^[a-z0-9.:\/-]+$/i.test(edgeUrl)) throw new Error('Invalid public edge URL');
  }
  const withConnection = (result) => result.credential && edgeUrl ? { ...result, credential: {
    ...result.credential, agent_env: { ...result.credential.agent_env, EDGE_HTTP_URL: edgeUrl,
      EDGE_WS_URL: `${edgeUrl.replace(/^https/, 'wss')}/_fastdog/tunnel` },
  } } : result;
  const commandKey = (tid, host) => `${tid}:${host}`;
  const commandIssued = (tid, host) => Boolean(store.read('connect_commands', {})[commandKey(tid, host)]);
  const markCommand = (tid, host) => { const all = store.read('connect_commands', {}); all[commandKey(tid, host)] = new Date(now()).toISOString(); store.write('connect_commands', all); };
  const store = createStore(dataDir);
  mailer ||= createFileMailer({ outboxDir: config.outboxDir || join(dataDir, 'outbox') });
  const notifications = createFileMailer({ outboxDir: config.outboxDir || join(dataDir, 'outbox') });
  const sessions = createSessions(store, now);
  const limits = createRateLimits(now, store);
  const auth = createAuth({ store, sessions, limits, now, mailer, config });
  const server = http.createServer(async (request, response) => {
    const started = now();
    let template = 'unknown';
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    response.setHeader('X-Robots-Tag', 'noindex');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('Cache-Control', 'no-store');
    response.on('finish', () => {
      try { config.logger?.({ method: request.method, route: template, status: response.statusCode, duration: Math.max(0, now() - started) }); }
      catch { /* Logging cannot affect a response. */ }
    });
    const send = (status, data, headers = {}) => {
      response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
      response.end(JSON.stringify(data));
    };
    try {
      const path = safePath(request.url);
      const pagePath = path.replace(/\/$/, '') || '/';
      if (!path.startsWith('/api/')) {
        if (request.method !== 'GET') throw fail('method_not_allowed');
        if (pagePath === '/health') return send(200, { ok: true });
        if (Object.hasOwn(pages, pagePath) && !['/login', '/signup', '/verify-email'].includes(pagePath)) {
          const session = sessions.get(request.headers.cookie);
          if (!auth.identity(session)) {
            response.writeHead(302, { Location: '/login', 'Content-Type': 'text/html; charset=utf-8' });
            return response.end('<!doctype html><html lang="en"><head><meta name="robots" content="noindex"><title>Sign in</title></head><body><main><a href="/login">Sign in to your portal</a></main></body></html>');
          }
          response.setHeader('Set-Cookie', session.cookie);
        }
        template = 'static';
        return serveStatic(path, response);
      }
      const match = path.match(/^\/api\/hostnames\/([^/]+)(?:\/(verify|rotate|agent))?$/);
      const allowed = staticRoutes.get(path) || (match ? (match[2] === 'agent' ? ['GET'] : match[2] ? ['POST'] : ['GET', 'DELETE']) : null);
      if (!allowed) throw fail('not_found');
      template = match ? `/api/hostnames/:hostname${match[2] ? `/${match[2]}` : ''}` : path;
      if (!allowed.includes(request.method)) return send(405, { error: 'method_not_allowed' }, { Allow: allowed.join(', ') });
      const ip = clientIp(request, config.trustProxy);
      let session = sessions.get(request.headers.cookie);
      if (session) response.setHeader('Set-Cookie', session.cookie);
      if (request.method !== 'GET' && (request.headers.origin !== config.origin || !session || !equal(request.headers['x-fd-csrf'], session.csrf))) throw fail('unauthorized');
      if (path === '/api/me') {
        if (!session) {
          limits.take(`bootstrap:${ip}`, 60, 3600000);
          session = sessions.create();
          response.setHeader('Set-Cookie', session.cookie);
        }
        const identity = auth.identity(session);
        return send(200, { email: identity?.user.email ?? null,
          tenant: identity ? pick(identity.tenant, ['id', 'plan', 'hostname_limit']) : null,
          email_verified: Boolean(identity?.user.email_verified_at), csrf: session.csrf });
      }
      const body = request.method === 'GET' ? {} : await readBody(request);
      if (authPaths.has(path)) return await auth.handle(path, body, { ip, session, send });
      const identity = auth.identity(session);
      if (!identity) throw fail('unauthorized');
      if (path === '/api/domains/search') {
        limits.take(`search:user:${ip}`, 30, 600000);
        const query = new URL(request.url, config.origin).searchParams.get('q');
        if (!query || query.length > 253 || /[\s\x00-\x1f\x7f]/.test(query)) throw fail('invalid_hostname');
        const result = await domainSearch.search(query, ip);
        if (result.error) throw fail(result.error === 'invalid_domain' ? 'invalid_hostname' : Object.hasOwn(statuses, result.error) ? result.error : 'internal_error');
        return send(200, result);
      }
      if (!identity) throw fail('unauthorized');
      const { user, tenant } = identity;
      if (path === '/api/plan') return send(200, pick(tenant, ['plan', 'hostname_limit']));
      if (path === '/api/domain-requests') {
        const all = store.read('domain_requests', []);
        if (request.method === 'GET') return send(200, { requests: all.filter((r) => r.tenant_id === tenant.id) });
        if (!user.email_verified_at) throw fail('unauthorized');
        const name = normalizeHostname(body.name ?? body.domain);
        if (all.filter((r) => r.tenant_id === tenant.id && !['registered', 'rejected', 'cancelled'].includes(r.status)).length >= 3) throw fail('invalid_limit');
        const quoted = body.quoted_price ?? body.price_year ?? null;
        if (quoted !== null && !/^\d{1,9}(?:\.\d{1,2})?$/.test(String(quoted))) throw fail('invalid_json');
        const record = { id: randomUUID(), tenant_id: tenant.id, name, quoted_price: quoted,
          currency: 'USD', status: 'requested', notes: '', created_at: new Date(now()).toISOString() };
        all.push(record);
        store.write('domain_requests', all);
        await notifications.send({ to: config.notificationTo || 'operator', kind: 'domain-request', link: `${config.origin}/domains#request=${record.id}` });
        return send(201, record);
      }
      if (path === '/api/hostnames') {
        if (request.method === 'GET') {
          const result = await edge.listHostnames(tenant.id);
          return send(200, { hostnames: result.hostnames.map((item) => ({ ...hostnameRecord(item), command_issued: commandIssued(tenant.id, item.hostname) })) });
        }
        if (!user.email_verified_at) throw fail('unauthorized');
        const hostname = normalizeHostname(body.hostname);
        return send(201, hostnameRecord(await edge.createHostname(tenant.id, hostname, tenant.hostname_limit)));
      }
      const hostname = normalizeHostname(match[1]);
      if (request.method === 'DELETE') {
        const removed = pick(await edge.deleteHostname(tenant.id, hostname), ['hostname', 'detached']);
        const all = store.read('connect_commands', {});
        if (delete all[commandKey(tenant.id, hostname)]) store.write('connect_commands', all);
        return send(200, removed);
      }
      if (!match[2]) return send(200, hostnameRecord(await edge.getHostname(tenant.id, hostname)));
      if (match[2] === 'agent') return send(200, pick(await edge.getAgent(tenant.id, hostname), ['connected', 'last_seen', 'registered_at']));
      if (!user.email_verified_at) throw fail('unauthorized');
      if (match[2] === 'verify') {
        limits.take(`verify:${tenant.id}`, 6, 60000);
        return send(200, pick(withConnection(await edge.verifyHostname(tenant.id, hostname)), ['hostname', 'status', 'verified', 'verified_at', 'method', 'checks', 'credential']));
      }
      limits.take(`rotate:${tenant.id}:${hostname}`, 5, 86400000, true);
      const rotated = pick(withConnection(await edge.rotateCredential(tenant.id, hostname)), ['credential']);
      markCommand(tenant.id, hostname);
      return send(200, rotated);
    } catch (error) {
      const code = Object.hasOwn(statuses, error.code) ? error.code : 'internal_error';
      const retry = Number.isFinite(error.retry_after) && error.retry_after > 0 ? Math.ceil(error.retry_after) : 60;
      if (!response.headersSent) send(statuses[code], { error: code, ...(code === 'rate_limited' ? { retry_after: retry } : {}) }, code === 'rate_limited' ? { 'Retry-After': String(retry) } : {});
      else response.end();
    }
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  return server;
}
