import { createStore, emptyAccounts } from './store.js';
import { token, digest, normalizeEmail } from './tokens.js';
export function createInvites({ dataDir, now = Date.now }) {
  const store = createStore(dataDir);
  return {
    mint({ email, expiresAt, plan, hostnameLimit }) {
      email = normalizeEmail(email);
      const expires = expiresAt === undefined ? now() + 7 * 86400000 : new Date(expiresAt).getTime();
      if (!email || !Number.isFinite(expires) || expires <= now()
        || (plan !== undefined && (typeof plan !== 'string' || !plan.trim() || plan.length > 100))
        || (hostnameLimit !== undefined && (!Number.isInteger(hostnameLimit) || hostnameLimit < 1 || hostnameLimit > 1000))) {
        throw new Error('Invalid invite settings');
      }
      const code = token();
      const data = store.read('accounts', emptyAccounts());
      data.invites.push({ code_hash: digest(code), email, expires_at: expires, plan, hostname_limit: hostnameLimit, redeemed_at: null });
      store.write('accounts', data);
      return code;
    },
  };
}
export function findInvite(data, code, email, now) {
  if (typeof code !== 'string' || code.length > 256) return undefined;
  return data.invites.find((invite) => invite.code_hash === digest(code) && invite.email === email
    && invite.redeemed_at == null && invite.expires_at > now);
}
