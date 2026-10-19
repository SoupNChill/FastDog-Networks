// Trial pause on the request path (docs/decisions/2026-10-19-trial-pause.md). The set of paused hostnames is
// the active claims of tenants listed in paused_tenants.json, rebuilt on routesChanged and at most every 30s.
// Fail-open: a read or parse error keeps the last good set (empty at startup), so a bad file never takes sites down.
import { readJson, dataDir as defaultDataDir } from '../onboard/json.js';

const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

export function createPausedHosts({ dataDir = defaultDataDir(), ttlMs = 30000, now = Date.now, warn = (message) => console.warn(message) } = {}) {
  let hosts = new Set();
  let builtAt = -Infinity;
  let failing = false;
  function rebuild() {
    builtAt = now();
    try {
      const state = readJson('paused_tenants.json', { tenants: {} }, dataDir);
      if (!plain(state) || !plain(state.tenants)) throw new Error('invalid');
      const tenants = new Set(Object.keys(state.tenants));
      const next = new Set();
      if (tenants.size) {
        const claims = readJson('tenant_hostnames.json', [], dataDir);
        if (!Array.isArray(claims)) throw new Error('invalid');
        for (const c of claims) if (c?.status === 'active' && tenants.has(c.tenant_id) && typeof c.hostname === 'string') next.add(c.hostname.toLowerCase());
      }
      hosts = next;
      failing = false;
    } catch {
      // One short warning per failure streak, never with hostnames.
      if (!failing) { try { warn('paused hosts: state unreadable; keeping last good set'); } catch { /* ignore */ } }
      failing = true;
    }
  }
  return {
    invalidate() { builtAt = -Infinity; },
    isPaused(hostname) {
      try {
        if (now() - builtAt >= ttlMs) rebuild();
        return hosts.has(String(hostname || '').split(':')[0].toLowerCase());
      } catch { return false; }
    },
  };
}

const escapeHtml = (value) => value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

export function upgradeUrl(value) {
  if (typeof value !== 'string' || !value) return null;
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url.href : null; } catch { return null; }
}

export function pausedPage(link) {
  const anchor = link ? `<p><a href="${escapeHtml(link)}">Site owner? Choose a plan</a></p>` : '';
  return '<!DOCTYPE html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    + '<meta name="robots" content="noindex"><title>Site paused</title>'
    + '<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;line-height:1.5;color:#222}</style></head>'
    + '<body><main><h1>Site paused</h1><p>This site is paused because its free trial has ended. The site owner can choose a plan to bring it back. Nothing has been deleted.</p>'
    + `${anchor}</main></body></html>\n`;
}

// Serves the paused page when the request belongs to a paused customer route. Returns true when it answered.
// Static operator routes and the default upstream are never paused; any internal error lets the request through.
export function servePaused(req, res, { resolved, tunnelHost, isPaused, link }) {
  let paused = false;
  try { paused = resolved?.kind !== 'static' && (resolved?.kind === 'tunnel' || tunnelHost === true) && isPaused(req.headers.host) === true; } catch { paused = false; }
  if (!paused) return false;
  const body = pausedPage(link);
  res.writeHead(503, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(body), 'retry-after': '3600',
    'cache-control': 'no-store', 'x-robots-tag': 'noindex', 'x-content-type-options': 'nosniff', 'x-fastdog-paused': '1' });
  res.end(req.method === 'HEAD' ? undefined : body);
  return true;
}
