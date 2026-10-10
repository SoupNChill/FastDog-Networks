import { token, digest } from './tokens.js';
export const DAY = 86400000;
export const cookieName = '__Host-fd_session';
export const sessionCookie = (value, seconds = 14 * 86400) => `${cookieName}=${value}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=${seconds}`;
export function createSessions(store, now) {
  function current() { return store.read('sessions', []).filter((s) => s.expires_at > now() && s.created_at + 90 * DAY > now()); }
  return {
    get(cookie) {
      const raw = String(cookie || '').split(';').map((part) => part.trim()).find((part) => part.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1);
      if (!raw || !/^[a-f0-9]{64}$/.test(raw)) return null;
      const all = current();
      const session = all.find((s) => s.token_hash === digest(raw));
      if (!session) return null;
      session.last_seen = now();
      session.expires_at = Math.min(now() + 14 * DAY, session.created_at + 90 * DAY);
      store.write('sessions', all);
      return { ...session, cookie: sessionCookie(raw, Math.floor((session.expires_at - now()) / 1000)) };
    },
    create(user = null) {
      const raw = token();
      const all = current();
      if (all.length >= 20000) throw new Error('Session capacity');
      const session = { token_hash: digest(raw), csrf: token(), user_id: user?.id ?? null,
        auth_version: user?.auth_version ?? null, created_at: now(), last_seen: now(), expires_at: now() + 14 * DAY };
      all.push(session);
      store.write('sessions', all);
      return { ...session, cookie: sessionCookie(raw) };
    },
    revoke(hash) { store.write('sessions', current().filter((s) => s.token_hash !== hash)); },
    revokeUser(id) { store.write('sessions', current().filter((s) => s.user_id !== id)); },
  };
}
