import { readFileSync, realpathSync } from 'node:fs';
import { dirname, resolve, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fail } from './errors.js';
const root = dirname(fileURLToPath(import.meta.url));
const publicRoot = resolve(root, '../public');
const siteRoot = resolve(root, '../../site');
const pages = { '/': 'hostname.html', '/login': 'login.html', '/signup': 'signup.html', '/hostname': 'hostname.html',
  '/connect': 'connect.html', '/domains': 'domains.html', '/plan': 'plan.html' };
const types = { '.svg': 'image/svg+xml', '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.ttf': 'font/ttf' };
export function safePath(raw) {
  if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//')) throw fail('not_found');
  let path;
  try { path = decodeURIComponent(raw.split('?')[0]); } catch { throw fail('not_found'); }
  if (/[\\\x00-\x1f\x7f%]/.test(path) || path.split('/').some((part) => part === '.' || part === '..')) throw fail('not_found');
  return path;
}
export function serveStatic(path, response) {
  let base = publicRoot;
  let relative = pages[path.replace(/\/$/, '') || '/'];
  if (/^\/js\/[a-z-]+\.js$/.test(path)) relative = path.slice(1);
  if (['/favicon.svg', '/logos/hound-dark.svg', '/logos/hound-light.svg'].includes(path) || path === '/css/site.css' || path === '/css/portal.css' || /^\/fonts\/[A-Za-z-]+\.ttf$/.test(path)) {
    base = siteRoot;
    relative = path.slice(1);
  }
  if (!relative) throw fail('not_found');
  try {
    const file = realpathSync(resolve(base, relative));
    if (!file.startsWith(`${base}${sep}`)) throw fail('not_found');
    const content = readFileSync(file);
    response.writeHead(200, { 'Content-Type': types[extname(file)], 'Cache-Control': 'no-store' });
    response.end(content);
  } catch { throw fail('not_found'); }
}
