import { randomUUID } from 'node:crypto';
import { emptyAccounts } from './store.js';
import { token, digest, normalizeEmail, tenantId } from './tokens.js';
import { hashPassword, verifyPassword, validPassword, dummyPassword } from './passwords.js';
import { findInvite } from './invites.js';
import { fail } from './errors.js';
import { sessionCookie } from './sessions.js';
import { createSignupGuard } from './signup-guard.js';

export function createAuth({ store, sessions, limits, now, mailer, config }) {
  const read = () => store.read('accounts', emptyAccounts());
  const generic = { ok: true };
  const guard = createSignupGuard({ limits, config, disposable: config.signupDisposable, bigmail: config.signupBigmail });
  // Open sign-up outcomes: a reason code only, never the email or its domain.
  const log = (outcome, reason) => {
    try { config.logger?.({ event: 'signup', source: 'open', outcome, ...(reason ? { reason } : {}), ...(reason === 'global_limit' ? { level: 'error', alert: 'signup_global_limit' } : {}) }); }
    catch { /* Logging cannot affect a response. */ }
  };
  function link(data, user, kind) {
    const raw = token();
    data.links = data.links.filter((item) => item.expires_at > now() && !(item.user_id === user.id && item.kind === kind));
    data.links.push({ token_hash: digest(raw), user_id: user.id, kind, expires_at: now() + 3600000 });
    return `${config.origin}/${kind === 'verify-email' ? 'verify-email' : 'login'}#${new URLSearchParams({ kind, token: raw, ...(kind === 'verify-email' && user.signup_source === 'open' ? { setup: '1' } : {}) })}`;
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
        limits.take(`signup:${ip}`, config.openSignup ? config.signupIpPerHour : 3, 3600000, config.openSignup);
        if (!email || !validPassword(body.password)) return send(200, generic);
        // Derive before checking the invite to keep invalid invites and existing accounts indistinguishable.
        const password_hash = await hashPassword(body.password);
        // Open sign-up applies only when no invite is offered; an invite always takes the invite path.
        const open = config.openSignup && (body.invite_code === undefined || body.invite_code === null || body.invite_code === '');
        if (open) {
          const reason = guard.check(email);
          if (reason) { log('refused', reason); return send(200, generic); }
        }
        const data = read();
        // Only expired, unverified open registrations may be reclaimed. Never release a tenant's claims.
        const stale = data.users.find((u) => u.email === email && !u.email_verified_at
          && data.tenants.some((t) => t.id === u.tenant_id && t.source === 'open' && t.status === 'active')
          && !data.links.some((item) => item.user_id === u.id && item.kind === 'verify-email' && item.expires_at > now()));
        if (open && stale) {
          stale.password_hash = password_hash;
          stale.auth_version++;
          stale.signup_source = 'open';
          data.links = data.links.filter((item) => item.user_id !== stale.id);
          const url = link(data, stale, 'verify-email');
          store.write('accounts', data);
          sessions.revokeUser(stale.id);
          log('reclaimed', null);
          await mailer.send({ to: email, kind: 'verify-email', link: url });
          return send(200, generic);
        }
        const invite = open ? null : findInvite(data, body.invite_code, email, now());
        if ((!open && !invite) || data.users.some((u) => u.email === email)) {
          if (open) log('refused', 'exists');
          return send(200, generic);
        }
        const tenant = open
          ? { id: tenantId(), name: '', plan: 'trial', hostname_limit: 1, status: 'active', source: 'open' }
          : { id: tenantId(), name: '', plan: invite.plan ?? config.defaultPlan,
            hostname_limit: invite.hostname_limit ?? config.defaultHostnameLimit, status: 'active' };
        const user = { id: randomUUID(), tenant_id: tenant.id, email, password_hash, email_verified_at: null, auth_version: 1, ...(open ? { signup_source: 'open' } : {}) };
        data.tenants.push(tenant);
        data.users.push(user);
        if (invite) {
          invite.redeemed_at = now();
          invite.tenant_id = tenant.id;
        }
        const url = link(data, user, 'verify-email');
        store.write('accounts', data);
        if (open) log('created', null);
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
        // Derive before reading mutable state; then recheck the one-use link after the await.
        const password_hash = validPassword(body.password) ? await hashPassword(body.password) : null;
        const data = read();
        const entry = findLink(data, body, 'verify-email');
        if (!entry) throw fail('unauthorized');
        const user = data.users.find((u) => u.id === entry.user_id);
        if (!user) throw fail('unauthorized');
        if (user.signup_source === 'open' || data.tenants.some((t) => t.id === user.tenant_id && t.source === 'open')) {
          if (!password_hash) throw fail('unauthorized');
          user.password_hash = password_hash;
          user.auth_version++;
          data.links = data.links.filter((item) => item.user_id !== user.id);
          sessions.revokeUser(user.id);
        }
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
