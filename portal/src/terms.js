import { createHash, randomBytes } from 'node:crypto';
export const TERMS_VERSION = '2026-10-17-draft';
export const PRIVACY_VERSION = '2026-10-19';
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

export function needsTermsUpdate(user) {
  const record = user.terms;
  return !record || typeof record !== 'object' || Array.isArray(record)
    || record.tos_version !== TERMS_VERSION || record.privacy_version !== PRIVACY_VERSION
    || typeof record.accepted_at !== 'string' || !Number.isFinite(Date.parse(record.accepted_at))
    || typeof record.ip_hash !== 'string' || !/^[a-f0-9]{64}$/.test(record.ip_hash);
}
export function termsUpdate(user, env, logger) {
  try {
    if (!user || !needsTermsUpdate(user)) return {};
    const urls = termsUrls(env);
    return { terms_update: { required: true, terms_url: urls.terms, privacy_url: urls.privacy,
      tos_version: TERMS_VERSION, privacy_version: PRIVACY_VERSION } };
  } catch {
    try { logger?.({ event: 'terms_check_failed', reason: 'check_failed' }); } catch { /* Logging is optional. */ }
    return {};
  }
}
// Keep the read/modify/write synchronous, like the other account updates.
export function acceptTerms(store, userId, ip, time, logger) {
  try {
    const data = store.read('accounts');
    const user = data.users.find((item) => item.id === userId);
    const next = termsRecord(store, ip, time);
    const history = Array.isArray(user.terms_history) ? user.terms_history : [];
    if (user.terms !== undefined) history.push(user.terms);
    user.terms_history = history.slice(-10);
    user.terms = next;
    store.write('accounts', data);
    return { ok: true };
  } catch {
    try { logger?.({ event: 'terms_accept_failed', reason: 'write_failed' }); } catch { /* Logging is optional. */ }
    return { ok: false };
  }
}
