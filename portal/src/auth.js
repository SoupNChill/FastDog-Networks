import { randomUUID } from 'node:crypto';
import { emptyAccounts } from './store.js';
import { token, digest, normalizeEmail, tenantId } from './tokens.js';
import { hashPassword, verifyPassword, validPassword, dummyPassword } from './passwords.js';
import { findInvite } from './invites.js';
import { fail } from './errors.js';
import { sessionCookie } from './sessions.js';

export function createAuth({ store, sessions, limits, now, mailer, config }) {
  const read = () => store.read('accounts', emptyAccounts());
  const generic = { ok: true };
  function link(data, user, kind) {
    const raw = token();
    data.links = data.links.filter((item) => item.expires_at > now() && !(item.user_id === user.id && item.kind === kind));
    data.links.push({ token_hash: digest(raw), user_id: user.id, kind, expires_at: now() + 3600000 });
    return `${config.origin}/login#${new URLSearchParams({ kind, token: raw })}`;
  }
  function findLink(data, body, kind) {
    return typeof body.token === 'string' && data.links.find((item) => item.token_hash === digest(body.token)
      && item.kind === kind && item.expires_at > now());
  }
  return {
    identity(session) {
      const data = read();
      const user = data.users.find((u) => u.id === session?.user_id && u.auth_version === session.auth_version);
      const tenant = data.tenants.find((t) => t.id === user?.tenant_id && t.status === 'active');
      return user && tenant ? { user, tenant } : null;
    },
    async handle(path, body, context) {
      const { ip, session, send } = context;
      const email = normalizeEmail(body.email);
      if (path === '/api/signup') {
        limits.take(`signup:${ip}`, 3, 3600000);
        if (!email || !validPassword(body.password)) return send(200, generic);
        // Derive before checking the invite to keep invalid invites and existing accounts indistinguishable.
        const password_hash = await hashPassword(body.password);
        const data = read();
        const invite = findInvite(data, body.invite_code, email, now());
        if (!invite || data.users.some((u) => u.email === email)) return send(200, generic);
        const tenant = { id: tenantId(), name: '', plan: invite.plan ?? config.defaultPlan,
          hostname_limit: invite.hostname_limit ?? config.defaultHostnameLimit, status: 'active' };
        const user = { id: randomUUID(), tenant_id: tenant.id, email, password_hash, email_verified_at: null, auth_version: 1 };
        data.tenants.push(tenant);
        data.users.push(user);
        invite.redeemed_at = now();
        invite.tenant_id = tenant.id;
        const url = link(data, user, 'verify-email');
        store.write('accounts', data);
        await mailer.send({ to: email, kind: 'verify-email', link: url });
        return send(200, generic);
      }
      if (path === '/api/login') {
        const accountKey = `login-account:${digest(email || '')}`;
        const ipKey = `login-ip:${ip}`;
        limits.take(ipKey, 20, 900000);
        limits.take(accountKey, 5, 900000, true);
        const initial = read().users.find((u) => u.email === email);
        const valid = await verifyPassword(body.password, initial?.password_hash || dummyPassword);
        const user = read().users.find((u) => u.id === initial?.id);
        if (!valid || !user || user.auth_version !== initial.auth_version) throw fail('unauthorized');
        limits.refund(ipKey);
        limits.refund(accountKey, true);
        const next = sessions.create(user);
        sessions.revoke(session.token_hash);
        return send(200, generic, { 'Set-Cookie': next.cookie });
      }
      if (path === '/api/logout') {
        sessions.revoke(session.token_hash);
        return send(200, generic, { 'Set-Cookie': sessionCookie('', 0) });
      }
      if (path === '/api/password-reset') {
        limits.take(`reset-ip:${ip}`, 10, 900000);
        limits.take(`reset-account:${digest(email || '')}`, 3, 900000);
        const data = read();
        const user = data.users.find((u) => u.email === email);
        if (user) {
          const url = link(data, user, 'password-reset');
          store.write('accounts', data);
          await mailer.send({ to: email, kind: 'password-reset', link: url });
        }
        return send(200, generic);
      }
      limits.take(`link:${ip}`, 20, 900000);
      if (path === '/api/verify-email') {
        const data = read();
        const entry = findLink(data, body, 'verify-email');
        if (!entry) throw fail('unauthorized');
        const user = data.users.find((u) => u.id === entry.user_id);
        if (!user) throw fail('unauthorized');
        user.email_verified_at = new Date(now()).toISOString();
        data.links = data.links.filter((item) => item !== entry);
        store.write('accounts', data);
        return send(200, generic);
      }
      if (path === '/api/password-reset/confirm') {
        if (!validPassword(body.password)) throw fail('unauthorized');
        const password_hash = await hashPassword(body.password);
        const data = read();
        const entry = findLink(data, body, 'password-reset');
        if (!entry) throw fail('unauthorized');
        const user = data.users.find((u) => u.id === entry.user_id);
        if (!user) throw fail('unauthorized');
        user.password_hash = password_hash;
        user.auth_version++;
        data.links = data.links.filter((item) => item.user_id !== user.id || item.kind !== 'password-reset');
        store.write('accounts', data);
        sessions.revokeUser(user.id);
        return send(200, generic, { 'Set-Cookie': sessionCookie('', 0) });
      }
      throw fail('not_found');
    },
  };
}
