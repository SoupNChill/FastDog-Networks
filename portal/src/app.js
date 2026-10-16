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
import { createConnectTokens, assistantPrompt } from './connect-tokens.js';
import { buildCommand, validOrigin } from './connect-command.js';

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
  if (record.agent) result.agent = pick(record.agent, ['connected', 'last_seen', 'registered_at', 'origin_reachable', 'origin_checked_at', 'origin_address', 'agent_version']);
  return result;
}
// Allow-list the edge status payload so nothing internal (paths, addresses) reaches the browser.
function siteStatus(value) {
  const result = pick(value, ['hostname', 'live', 'reasons', 'checked_at']);
  result.agent = pick(value.agent, ['connected', 'last_seen', 'origin_reachable', 'origin_checked_at', 'agent_version']);
  result.cert = value.cert ? pick(value.cert, ['valid', 'expires_at', 'issuer']) : null;
  result.traffic = pick(value.traffic, ['available', 'total', 'hourly', 'p50_ms', 'errors_5xx']);
  result.verdict = pick(value.verdict, ['available', 'shadow', 'scored', 'would_block', 'would_challenge']);
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
  const connectTokens = createConnectTokens(store, now);
  const docsUrl = typeof config.docsUrl === 'string' && /^https:\/\/[a-z0-9.-]+(?:\/[a-z0-9/_-]*)?$/i.test(config.docsUrl) ? config.docsUrl : null;
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
      if (path.startsWith('/api/connect/v1/')) {
        // Bearer-only API for AI assistants. Cookies are ignored here, so CSRF does not apply.
        template = path;
        const routes = { '/api/connect/v1/hostname': 'GET', '/api/connect/v1/command': 'POST' };
        if (!routes[path]) throw fail('not_found');
        if (request.method !== routes[path]) return send(405, { error: 'method_not_allowed' }, { Allow: routes[path] });
        limits.take(`connect-api:${clientIp(request, config.trustProxy)}`, 120, 600000);
        const header = request.headers.authorization;
        const record = connectTokens.find(typeof header === 'string' && /^Bearer /.test(header) ? header.slice(7).trim() : null);
        if (!record) throw fail('unauthorized');
        const accounts = store.read('accounts', { tenants: [], users: [] });
        const tenant = accounts.tenants.find((t) => t.id === record.tenant_id);
        const issuer = accounts.users.find((u) => u.id === record.user_id && u.tenant_id === record.tenant_id);
        // A password reset (auth_version bump) or a suspended tenant ends every token that user issued.
        if (!tenant || (tenant.status && tenant.status !== 'active') || !issuer || (issuer.auth_version ?? null) !== (record.auth_version ?? null)) throw fail('unauthorized');
        limits.take(`connect-token:${record.id}`, 30, 60000);
        // Re-check ownership on every call: a hostname removed or detached anywhere ends its tokens.
        let claim;
        try { claim = await edge.getHostname(record.tenant_id, record.hostname); }
        catch (error) {
          if (error.code === 'hostname_not_found') { connectTokens.revokeAll(record.tenant_id, record.hostname); throw fail('unauthorized'); }
          throw error;
        }
        // Same tenant re-adding the hostname creates a new claim; tokens for the old claim end.
        if (record.claim_created_at && claim.created_at !== record.claim_created_at) { connectTokens.revokeAll(record.tenant_id, record.hostname); throw fail('unauthorized'); }
        if (claim.status !== 'active') throw fail('not_active');
        if (path === '/api/connect/v1/hostname') {
          const agent = pick(await edge.getAgent(record.tenant_id, record.hostname), ['connected', 'last_seen', 'origin_reachable', 'origin_checked_at']);
          return send(200, { hostname: record.hostname, scope: 'connect', expires_at: record.expires_at, command_issued: Boolean(record.command_issued_at), agent });
        }
        const body = await readBody(request);
        const upstream = validOrigin(body.origin);
        const platform = body.platform === undefined ? 'linux' : body.platform;
        if (!upstream || !['linux', 'docker'].includes(platform)) throw fail('invalid_origin');
        if (!edgeUrl) throw fail('internal_error');
        if (record.command_issued_at) throw fail('token_used');
        // Token-driven rotations get their own small budget on top of the shared 5/day rotate limit,
        // so a leaked prompt cannot use up the customer's own rotations.
        limits.take(`connect-token-rotate:${record.tenant_id}:${record.hostname}`, 3, 86400000, true);
        try { limits.take(`rotate:${record.tenant_id}:${record.hostname}`, 5, 86400000, true); }
        catch (error) { limits.refund(`connect-token-rotate:${record.tenant_id}:${record.hostname}`, true); throw error; }
        if (!connectTokens.markCommand(record.id)) throw fail('token_used');
        let command;
        try {
          const rotated = withConnection(await edge.rotateCredential(record.tenant_id, record.hostname));
          command = buildCommand(rotated.credential?.agent_env, { platform, portalOrigin: config.origin, origin: upstream });
          if (!command) throw fail('internal_error');
          markCommand(record.tenant_id, record.hostname);
        } catch (error) {
          // Nothing usable was returned: the token and both budgets stay available for a retry.
          connectTokens.unmarkCommand(record.id);
          limits.refund(`connect-token-rotate:${record.tenant_id}:${record.hostname}`, true);
          limits.refund(`rotate:${record.tenant_id}:${record.hostname}`, true);
          throw error;
        }
        return send(200, { hostname: record.hostname, platform, origin: upstream, command,
          note: 'Run this once on the server where the app runs. It replaces any earlier connection for this website and contains a private key; do not log or share it. Delete fastdog-agent.env (Docker) after the container starts if you keep no copy.' });
      }
      const match = path.match(/^\/api\/hostnames\/([^/]+)(?:\/(verify|rotate|agent|status|test|connect-token))?$/);
      const allowed = staticRoutes.get(path) || (match ? (match[2] === 'connect-token' ? ['GET', 'POST', 'DELETE'] : ['agent', 'status'].includes(match[2]) ? ['GET'] : match[2] ? ['POST'] : ['GET', 'DELETE']) : null);
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
        const created = hostnameRecord(await edge.createHostname(tenant.id, hostname, tenant.hostname_limit));
        const commands = store.read('connect_commands', {});
        if (delete commands[commandKey(tenant.id, hostname)]) store.write('connect_commands', commands);
        return send(201, created);
      }
      const hostname = normalizeHostname(match[1]);
      if (request.method === 'DELETE' && !match[2]) {
        const removed = pick(await edge.deleteHostname(tenant.id, hostname), ['hostname', 'detached']);
        connectTokens.revokeAll(tenant.id, hostname);
        const all = store.read('connect_commands', {});
        if (delete all[commandKey(tenant.id, hostname)]) store.write('connect_commands', all);
        return send(200, removed);
      }
      if (!match[2]) return send(200, hostnameRecord(await edge.getHostname(tenant.id, hostname)));
      if (match[2] === 'connect-token') {
        const record = await edge.getHostname(tenant.id, hostname);
        if (request.method === 'GET') return send(200, { tokens: connectTokens.list(tenant.id, hostname) });
        if (request.method === 'DELETE') return send(200, { revoked: connectTokens.revokeAll(tenant.id, hostname) });
        if (!user.email_verified_at) throw fail('unauthorized');
        if (record.status !== 'active') throw fail('not_active');
        limits.take(`connect-token:${tenant.id}`, 5, 3600000, true);
        const issued = connectTokens.issue(tenant.id, hostname, { user_id: user.id, auth_version: user.auth_version, claim_created_at: record.created_at });
        return send(201, { ...issued, hostname, scope: 'connect',
          prompt: assistantPrompt({ hostname, token: issued.token, expiresAt: issued.expires_at, portalOrigin: config.origin, docsUrl }) });
      }
      if (match[2] === 'agent') return send(200, pick(await edge.getAgent(tenant.id, hostname), ['connected', 'last_seen', 'registered_at', 'origin_reachable', 'origin_checked_at', 'origin_address', 'agent_version']));
      if (match[2] === 'status') {
        limits.take(`status:${tenant.id}`, 60, 60000);
        return send(200, siteStatus(await edge.getStatus(tenant.id, hostname)));
      }
      if (match[2] === 'test') {
        limits.take(`test:${tenant.id}`, 6, 60000);
        return send(200, pick(await edge.testSite(tenant.id, hostname), ['hostname', 'tested_at', 'ok', 'status', 'ms', 'error', 'cert']));
      }
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
