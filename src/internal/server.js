import http from 'node:http';
import { isIP } from 'node:net';
import { equalToken } from '../control/auth.js';
import { normalizeHostname } from '../onboard/hostname.js';
import { createClaims, fail } from './claims.js';
import { createTlsAsk } from './tls-ask.js';
import { createSiteStatus } from './site-status-service.js';

export function isLoopback(address) {
  return address === '::1' || (isIP(address) === 4 && address.startsWith('127.')) ||
    (address?.startsWith('::ffff:') && isIP(address.slice(7)) === 4 && address.slice(7).startsWith('127.'));
}

export function assertLoopbackBind(bind) {
  if (!isLoopback(bind)) throw new Error('INTERNAL_BIND must be a loopback address');
  return bind;
}

function send(res, status, body) {
  if (res.writableEnded || res.destroyed) return;
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store',
    ...(body?.retry_after ? { 'retry-after': String(body.retry_after) } : {}) });
  res.end(body === undefined ? '' : JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('error', () => reject(fail(400, 'invalid_json')));
    req.on('aborted', () => reject(fail(400, 'invalid_json')));
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 16384) { reject(fail(413, 'payload_too_large')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (size > 16384) return;
      if (!size) return resolve({});
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
        resolve(body);
      } catch { reject(fail(400, 'invalid_json')); }
    });
  });
}

export function createInternalServer(opts = {}) {
  if (typeof opts.portalKey !== 'string' || opts.portalKey.length < 32 || equalToken(opts.portalKey, opts.agentToken)) {
    throw new Error('PORTAL_KEY must contain at least 32 characters and differ from AGENT_TOKEN');
  }
  const server = http.createServer({ requestTimeout: 5000, headersTimeout: 5000, connectionsCheckingInterval: 1000 }, handle);
  server.setTimeout(5000);
  const claims = createClaims(opts, () => server.emit('routesChanged'));
  const tlsAskEnabled = opts.tlsAskEnabled ?? (process.env.TLS_ASK_ENABLED === '1');
  const tlsAsk = createTlsAsk({ ...opts, tlsAskEnabled });
  const siteStatus = createSiteStatus({ ...opts, agent: (tid, host) => claims.agent(tid, host), claimSince: (tid, host) => claims.claimSince(tid, host) });

  if (opts.recheckEnabled) {
    let timer;
    server.once('listening', () => {
      timer = setInterval(() => {
        claims.recheckActiveClaims().catch(() => server.emit('recheckError'));
      }, 6 * 60 * 60 * 1000);
      timer.unref();
    });
    server.once('close', () => clearInterval(timer));
  }

  async function handle(req, res) {
    const started = performance.now();
    const abort = new AbortController();
    let route = 'not_found';
    const timer = setTimeout(() => {
      abort.abort();
      send(res, 400, { error: 'invalid_json' });
      req.destroy();
    }, 5000);
    res.once('close', () => { clearTimeout(timer); if (!res.writableFinished) abort.abort(); });
    res.once('finish', () => {
      clearTimeout(timer);
      const event = route === '/tls/ask' ? { status: res.statusCode } :
        { method: req.method, route, status: res.statusCode, duration: (performance.now() - started) / 1000 };
      try {
        if (typeof opts.logger === 'function') opts.logger(event);
        else opts.logger?.info?.(event);
      } catch { /* Logging must not affect the response. */ }
    });
    try {
      const url = new URL(req.url, 'http://internal.invalid');
      const pathname = url.pathname.replace(/^\/internal\/v1(?=\/)/, '');
      if (pathname === '/health' || pathname === '/tls/ask') {
        route = pathname;
        if (pathname === '/tls/ask' && !tlsAskEnabled) return send(res, 404);
        if (req.method !== 'GET') throw fail(405, 'method_not_allowed');
        if (pathname === '/health') return send(res, 200, { ok: true });
        if (!isLoopback(req.socket.remoteAddress) || Object.keys(req.headers).some((name) => name === 'forwarded' || name.startsWith('x-forwarded-'))) return send(res, 404);
        const client = req.socket.remoteAddress.replace(/^::ffff:/, '');
        const result = tlsAsk(url.searchParams.get('domain'), client);
        return send(res, result.status, result.retry_after ? { error: 'rate_limited', retry_after: result.retry_after } : undefined);
      }
      if (!equalToken(req.headers['x-fastdog-portal-key'], opts.portalKey)) throw fail(401, 'unauthorized');
      const match = url.pathname.match(/^\/internal\/v1\/tenants\/([^/]+)\/hostnames(?:\/([^/]+)(?:\/(verify|credentials\/rotate|agent|status|test))?)?$/);
      if (!match) throw fail(404, 'not_found');
      const [, tid, rawHost, action] = match;
      route = '/internal/v1/tenants/:tid/hostnames' + (rawHost ? '/:hostname' : '') + (action ? `/${action}` : '');
      if (!/^t_[a-z2-7]{20}$/.test(tid)) throw fail(400, 'invalid_tenant');
      const allowed = !rawHost ? ['GET', 'POST'] : ['agent', 'status'].includes(action) ? ['GET'] : action ? ['POST'] : ['GET', 'DELETE'];
      if (!allowed.includes(req.method)) throw fail(405, 'method_not_allowed');
      if (Number(req.headers['content-length']) > 16384) throw fail(413, 'payload_too_large');
      const body = await readBody(req);
      if (abort.signal.aborted) return;
      if (!rawHost) {
        if (req.method === 'GET') return send(res, 200, claims.list(tid));
        const result = claims.create(tid, body);
        return send(res, result.status, result.body);
      }
      let decoded;
      try { decoded = decodeURIComponent(rawHost); } catch { throw fail(400, 'invalid_hostname'); }
      const host = normalizeHostname(decoded);
      let result;
      if (action === 'verify') result = await claims.verify(tid, host, abort.signal);
      else if (action === 'credentials/rotate') result = claims.rotate(tid, host);
      else if (action === 'agent') result = claims.agent(tid, host);
      else if (action === 'status') result = await siteStatus.status(tid, host);
      else if (action === 'test') result = await siteStatus.test(tid, host);
      else if (req.method === 'DELETE') result = claims.delete(tid, host);
      else result = claims.get(tid, host);
      send(res, 200, result);
    } catch (error) {
      const status = error.status ?? 500;
      send(res, status, { error: status === 500 ? 'internal_error' : error.code,
        ...(error.retry_after ? { retry_after: error.retry_after } : {}) });
    }
  }
  return server;
}
