import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';

/**
 * Forward an incoming Node req/res to an upstream URL (path + query preserved).
 * Minimal HTTP proxy suitable for Phase 1 LAN dogfood.
 */
export function forwardHttp(req, res, upstreamBase, opts = {}) {
  let target;
  try {
    target = new URL(req.url || '/', upstreamBase.endsWith('/') ? upstreamBase : `${upstreamBase}/`);
    // URL(req.url, base) resolves path correctly
    target = new URL(req.url || '/', upstreamBase);
  } catch (err) {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'bad_upstream', detail: String(err.message) }));
    return;
  }

  const isHttps = target.protocol === 'https:';
  const lib = isHttps ? https : http;
  const headers = { ...req.headers, host: target.host };
  delete headers['transfer-encoding'];
  if (opts.extraHeaders) Object.assign(headers, opts.extraHeaders);

  const proxyReq = lib.request(
    {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (isHttps ? 443 : 80),
      path: target.pathname + target.search,
      method: req.method,
      headers,
      timeout: opts.timeoutMs || 30000,
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
      proxyRes.pipe(res);
    },
  );

  proxyReq.on('error', (err) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'upstream_unreachable', detail: err.message, upstream: upstreamBase }));
    } else {
      res.destroy();
    }
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy(new Error('upstream timeout'));
  });

  req.pipe(proxyReq);
}
