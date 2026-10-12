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
      if (peers.length >= (user === null ? 5000 : 20000)) {
        if (user !== null) throw fail('rate_limited', Math.max(1, Math.ceil((Math.min(...peers.map((s) => Math.min(s.expires_at, s.created_at + 90 * DAY))) - now()) / 1000)));
        peers.sort((a, b) => a.created_at - b.created_at);
        const evicted = new Set(peers.slice(0, peers.length - 4999));
        for (let i = all.length - 1; i >= 0; i--) if (evicted.has(all[i])) all.splice(i, 1);
      }
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
