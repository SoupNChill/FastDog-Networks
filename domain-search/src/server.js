import http from 'node:http';
import { createRegistrar } from './registrar.js';
import { createService } from './service.js';

function normalizeIp(value) {
  if (typeof value !== 'string' || value.length > 64) return 'unknown';
  const ip = value.trim().toLowerCase();
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)
    && ip.split('.').every((part) => Number(part) <= 255)) return ip.split('.').map(Number).join('.');
  if (!/^[\da-f:.]+$/.test(ip) || !ip.includes(':')) return 'unknown';
  try {
    const canonical = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
    const [left, right] = canonical.split('::');
    const start = left ? left.split(':') : [];
    const end = right ? right.split(':') : [];
    const groups = right === undefined ? start : [...start, ...Array(8 - start.length - end.length).fill('0'), ...end];
    const expanded = groups.map((part) => parseInt(part, 16));
    if (expanded.slice(0, 5).every((part) => part === 0) && expanded[5] === 65535) {
      return [expanded[6] >> 8, expanded[6] & 255, expanded[7] >> 8, expanded[7] & 255].join('.');
    }
    return expanded.map((part) => part.toString(16)).join(':');
  } catch { return 'unknown'; }
}

export function truncateIp(value) {
  const ip = normalizeIp(value);
  if (ip.includes('.')) return `${ip.split('.').slice(0, 3).join('.')}.0/24`;
  if (ip.includes(':')) return `${ip.split(':').slice(0, 3).join(':')}::/48`;
  return 'unknown';
}

export function createServer({
  service = createService({ registrar: createRegistrar() }),
  trustProxy = process.env.TRUST_PROXY === '1',
  logger = (line) => console.log(line),
} = {}) {
  return http.createServer(async (request, response) => {
    const started = Date.now();
    const forwarded = request.headers['x-forwarded-for'];
    const ip = normalizeIp(trustProxy && typeof forwarded === 'string'
      ? forwarded.split(',')[0] : request.socket.remoteAddress);
    let path = 'unknown';
    const send = (status, body, headers = {}) => {
      response.writeHead(status, {
        'Cache-Control': 'no-store',
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff',
        ...headers,
      });
      response.end(JSON.stringify(body));
    };
    response.on('finish', () => {
      // Log only known paths, never arbitrary path/query text or upstream details.
      try { logger(`${path} ${response.statusCode} ${Date.now() - started}ms ${truncateIp(ip)}`); }
      catch { /* Logging must not affect service availability. */ }
    });
    try {
      const url = new URL(request.url, 'http://localhost');
      if (['/api/domains/search', '/api/domains/health'].includes(url.pathname)) path = url.pathname;
      if (request.method !== 'GET') return send(405, { error: 'method_not_allowed' }, { Allow: 'GET' });
      if (path === '/api/domains/health') return send(200, { ok: true });
      if (path !== '/api/domains/search') return send(404, { error: 'not_found' });
      const limit = service.rateLimit(ip);
      if (!limit.allowed) return send(429, { error: 'rate_limited' }, { 'Retry-After': String(limit.retryAfter) });
      const result = await service.search(url.searchParams.get('q'));
      return send(result.error === 'invalid_domain' ? 400 : 200, result);
    } catch {
      return send(503, { error: 'unavailable', degraded: 'upstream_unavailable' });
    }
  });
}

if (process.argv[1] && import.meta.url === new URL(process.argv[1], 'file:').href) {
  createServer().listen(Number(process.env.DOMAIN_SEARCH_PORT || 8791), process.env.DOMAIN_SEARCH_BIND || '127.0.0.1');
}
