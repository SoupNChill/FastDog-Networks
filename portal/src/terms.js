import { createHash, randomBytes } from 'node:crypto';
export const TERMS_VERSION = '2026-10-17-draft';
export const PRIVACY_VERSION = '2026-10-17-draft';
const siteFallback = 'https://example.invalid';
export function siteOrigin(env = process.env) {
  const raw = String(env.SITE_ORIGIN || '').trim().replace(/\/$/, '');
  try { return new URL(raw).protocol === 'https:' && new URL(raw).origin === raw ? raw : siteFallback; } catch { return siteFallback; }
}
export const termsUrls = (env = process.env) => {
  const origin = siteOrigin(env);
  return { terms: `${origin}/terms/`, privacy: `${origin}/privacy/`, faq: `${origin}/faq/` };
};
// Per-install salt lives in the private state directory so IP hashes cannot be compared across installs.
function installSalt(store) {
  const saved = store.read('install-salt', null);
  if (typeof saved?.salt === 'string') return saved.salt;
  const salt = randomBytes(32).toString('hex');
  store.write('install-salt', { salt });
  return salt;
}
export function termsRecord(store, ip, time) {
  return { tos_version: TERMS_VERSION, privacy_version: PRIVACY_VERSION, accepted_at: new Date(time).toISOString(),
    ip_hash: createHash('sha256').update(`${installSalt(store)}:${ip}`).digest('hex') };
}
