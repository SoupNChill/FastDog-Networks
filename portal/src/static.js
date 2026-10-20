import { readFileSync, realpathSync } from 'node:fs';
import { dirname, resolve, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fail } from './errors.js';
import { termsUrls } from './terms.js';
const root = dirname(fileURLToPath(import.meta.url));
const publicRoot = resolve(root, '../public');
export const pages = { '/': 'hostname.html', '/login': 'login.html', '/signup': 'signup.html', '/hostname': 'hostname.html',
  '/verify-email': 'verify-email.html', '/dashboard': 'hostname.html', '/start': 'start.html', '/connect': 'connect.html', '/domains': 'domains.html', '/plan': 'plan.html', '/status': 'status.html', '/keys': 'keys.html' };
const types = { '.sh': 'text/plain; charset=utf-8', '.svg': 'image/svg+xml', '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.ttf': 'font/ttf' };
const supportFallback = 'support@example.invalid';
export function supportEmail(env = process.env) {
  const value = String(env.PORTAL_SUPPORT_EMAIL || '').trim();
  return /^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/.test(value) ? value : supportFallback;
}
// /signup is rendered for the server's open_signup flag so the page is right before (or without) JavaScript.
// Anything but openSignup === true renders the invite-only form; signup.js applies the same copy after /api/me.
export const signupCopy = Object.freeze({
  closed: Object.freeze({ SIGNUP_INTRO: 'Use the exact email address that received your invitation. Copy the invitation code from that email.',
    INVITE_LABEL: 'Invitation code', INVITE_REQUIRED: ' required',
    SIGNUP_HELP: 'No email yet? Check your spam folder and the email address and code in your invitation. If you already have an account, sign in below.' }),
  open: Object.freeze({ SIGNUP_INTRO: 'Start your 7-day free trial: 1 hostname, no card needed.',
    INVITE_LABEL: 'Invitation code (optional)', INVITE_REQUIRED: '',
    SIGNUP_HELP: 'After you create your account, check your inbox and spam folder for a verification link. If you already have an account, sign in below.' }),
});
export function renderHtml(buffer, env = process.env, { openSignup = false } = {}) {
  const urls = termsUrls(env);
  let html = buffer.toString('utf8');
  for (const [name, value] of Object.entries(signupCopy[openSignup === true ? 'open' : 'closed'])) html = html.replaceAll(`{{${name}}}`, value);
  return Buffer.from(html.replaceAll('{{SUPPORT_EMAIL}}', supportEmail(env))
    .replaceAll('{{TERMS_URL}}', urls.terms).replaceAll('{{PRIVACY_URL}}', urls.privacy));
}
export function safePath(raw) {
  if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//')) throw fail('not_found');
  let path;
  try { path = decodeURIComponent(raw.split('?')[0]); } catch { throw fail('not_found'); }
  if (/[\\\x00-\x1f\x7f%]/.test(path) || path.split('/').some((part) => part === '.' || part === '..')) throw fail('not_found');
  return path;
}
export function serveStatic(path, response, { openSignup = false } = {}) {
  let base = publicRoot;
  let relative = pages[path.replace(/\/$/, '') || '/'];
  if (/^\/js\/[a-z-]+\.js$/.test(path)) relative = path.slice(1);
  if (['/favicon.svg', '/logos/hound-dark.svg', '/logos/hound-light.svg'].includes(path) || path === '/css/site.css' || path === '/css/portal.css' || path === '/css/guide.css' || path === '/css/connect.css' || path === '/css/status.css' || /^\/fonts\/[A-Za-z-]+\.ttf$/.test(path)) {
    base = publicRoot;
    relative = path.slice(1);
  }
  if (path === '/install/agent.sh') relative = 'install/agent.sh';
  if (!relative) throw fail('not_found');
  try {
    const file = realpathSync(resolve(base, relative));
    if (!file.startsWith(`${base}${sep}`)) throw fail('not_found');
    const content = extname(file) === '.html' ? renderHtml(readFileSync(file), process.env, { openSignup }) : readFileSync(file);
    response.writeHead(200, { 'Content-Type': types[extname(file)], 'Cache-Control': 'no-store' });
    response.end(content);
  } catch { throw fail('not_found'); }
}
