import { token, digest } from './tokens.js';
import { fail } from './errors.js';
export const DAY = 86400000;
export const cookieName = '__Host-fd_session';
export const sessionCookie = (value, seconds = 14 * 86400) => `${cookieName}=${value}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=${seconds}`;
const ANON_TTL = 30 * 60000;
const idleTTL = (session) => session.user_id === null ? ANON_TTL : 14 * DAY;
export function createSessions(store, now) {
  function current() { return store.read('sessions', []).filter((s) => Math.min(s.expires_at, s.last_seen + idleTTL(s)) > now() && s.created_at + 90 * DAY > now()); }
  return {
    get(cookie) {
      const raw = String(cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
      if (!raw || !/^[a-f0-9]{64}$/.test(raw)) return null;
      const all = current();
      const session = all.find((s) => s.token_hash === digest(raw));
      if (!session) return null;
      if (now() - session.last_seen >= 60000) {
        session.last_seen = now();
        session.expires_at = Math.min(now() + idleTTL(session), session.created_at + 90 * DAY);
        store.write('sessions', all);
      }
      return { ...session, cookie: sessionCookie(raw, Math.floor((session.expires_at - now()) / 1000)) };
    },
    create(user = null) {
      const raw = token();
      const all = current();
      const peers = all.filter((s) => (s.user_id === null) === (user === null));
      const userSessions = user === null ? [] : peers.filter((s) => s.user_id === user.id);
      const full = userSessions.length >= 10 ? userSessions : peers.length >= (user === null ? 5000 : 20000) ? peers : null;
      if (full) throw fail('rate_limited', Math.max(1, Math.ceil((Math.min(...full.map((s) =>
        Math.min(s.expires_at, s.last_seen + idleTTL(s), s.created_at + 90 * DAY))) - now()) / 1000)));
      const session = { token_hash: digest(raw), csrf: token(), user_id: user?.id ?? null,
        auth_version: user?.auth_version ?? null, created_at: now(), last_seen: now(), expires_at: now() + (user === null ? ANON_TTL : 14 * DAY) };
      all.push(session);
      store.write('sessions', all);
      return { ...session, cookie: sessionCookie(raw, (session.expires_at - now()) / 1000) };
    },
    revoke(hash) { store.write('sessions', current().filter((s) => s.token_hash !== hash)); },
    revokeUser(id) { store.write('sessions', current().filter((s) => s.user_id !== id)); },
  };
}
