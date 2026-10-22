// Scoped API keys v1 (docs/decisions/2026-10-16-scoped-api-keys.md).
// A key belongs to one tenant, carries one or more scopes, may be limited to exact hostnames,
// always expires (30 days by default, 90 at most), is revocable, and is stored only as a
// SHA-256 digest. The secret is returned once, at creation.
import { randomBytes, randomUUID } from 'node:crypto';
import { digest } from './tokens.js';
import { normalizeHostname } from './hostname.js';
import { fail } from './errors.js';

export const API_KEY_PREFIX = 'fdak_';
export const API_KEY_SCOPES = Object.freeze(['hostnames:create', 'status:read', 'connect']);
export const DAY_MS = 86400000;
export const DEFAULT_DAYS = 30;
export const MAX_DAYS = 90;
export const MAX_LIVE_PER_TENANT = 10;
// Trial keys (TRIAL_API_KEY_ENABLED, default off): one live key, exactly one hostname, never past the trial end.
export const TRIAL_MAX_LIVE = 1;
export const TRIAL_MAX_HOSTNAMES = 1;
const MAX_ALLOW_HOSTS = 20;
const AUDIT_KEEP_PER_TENANT = 1000;
const AUDIT_MAX_AGE_DAYS = 30;
const TOUCH_EVERY_MS = 60000;
// There is no free plan; these names are refused defensively in case one is ever assigned.
export const UNPAID_PLANS = new Set(['free', 'none', 'trial', 'suspended']);

export const planAllowsKeys = (tenant) => Boolean(tenant) && (!tenant.status || tenant.status === 'active')
  && typeof tenant.plan === 'string' && tenant.plan.trim() !== '' && !UNPAID_PLANS.has(tenant.plan.trim().toLowerCase());

export function createApiKeys(store, now) {
  // Expired or revoked records are kept for 30 days so the list can show recent history.
  const all = () => store.read('api_keys', []).filter((k) => Date.parse(k.revoked_at || k.expires_at) > now() - 30 * DAY_MS);
  const live = (k) => !k.revoked_at && Date.parse(k.expires_at) > now();
  const view = (k) => ({ id: k.id, name: k.name, prefix: k.prefix, scopes: [...k.scopes], hostnames: k.hostnames ? [...k.hostnames] : null,
    created_at: k.created_at, expires_at: k.expires_at, revoked_at: k.revoked_at, last_used_at: k.last_used_at ?? null,
    state: k.revoked_at ? 'revoked' : live(k) ? 'active' : 'expired', ...(k.trial ? { trial: true } : {}) });
  return {
    // trial: the tenant's active trial ({ ends_at }) when this is a trial key, else null (paid rules).
    parse(body, trial = null) {
      const name = body.name === undefined ? '' : body.name;
      if (typeof name !== 'string' || name.length > 60 || /[\x00-\x1f\x7f<>]/.test(name)) throw fail('invalid_key');
      const scopes = body.scopes;
      if (!Array.isArray(scopes) || !scopes.length || scopes.length > API_KEY_SCOPES.length
        || scopes.some((s) => !API_KEY_SCOPES.includes(s)) || new Set(scopes).size !== scopes.length) throw fail('invalid_key');
      let hostnames = null;
      if (body.hostnames !== undefined && body.hostnames !== null) {
        if (!Array.isArray(body.hostnames) || body.hostnames.length > MAX_ALLOW_HOSTS) throw fail('invalid_key');
        if (body.hostnames.length) {
          try { hostnames = [...new Set(body.hostnames.map((h) => normalizeHostname(h)))]; }
          catch { throw fail('invalid_key'); }
        }
      }
      if (trial && hostnames?.length !== TRIAL_MAX_HOSTNAMES) throw fail('invalid_key');
      // A trial key without a lifetime runs until the trial ends (within the 90-day maximum).
      const days = body.expires_in_days === undefined ? (trial ? MAX_DAYS : DEFAULT_DAYS) : body.expires_in_days;
      if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) throw fail('invalid_key');
      const parsed = { name: name.trim(), scopes: API_KEY_SCOPES.filter((s) => scopes.includes(s)), hostnames, days };
      if (!trial) return parsed;
      const ends = Date.parse(trial.ends_at);
      if (!Number.isFinite(ends) || ends <= now()) throw fail('plan_required');
      return { ...parsed, trial_ends: ends };
    },
    // Latest expiry a trial key created now can get.
    trialExpiry: (trial) => new Date(Math.min(Date.parse(trial.ends_at), now() + MAX_DAYS * DAY_MS)).toISOString(),
    create(tenantId, issuer, { name, scopes, hostnames, days, trial_ends }) {
      const records = all();
      const trial = trial_ends !== undefined;
      if (records.filter((k) => k.tenant_id === tenantId && live(k)).length >= (trial ? TRIAL_MAX_LIVE : MAX_LIVE_PER_TENANT)) throw fail('key_limit_reached');
      const secret = `${API_KEY_PREFIX}${randomBytes(32).toString('base64url')}`;
      const record = { id: randomUUID(), digest: digest(secret), prefix: secret.slice(0, 9), tenant_id: tenantId, name,
        scopes, hostnames, user_id: issuer.user_id, auth_version: issuer.auth_version ?? null,
        created_at: new Date(now()).toISOString(), expires_at: new Date(Math.min(now() + days * DAY_MS, trial ? trial_ends : Infinity)).toISOString(),
        revoked_at: null, last_used_at: null, ...(trial ? { trial: true } : {}) };
      records.push(record);
      store.write('api_keys', records);
      return { key: secret, ...view(record) };
    },
    // Live record for a bearer secret, or null. Never throws on malformed input.
    find(secret) {
      if (typeof secret !== 'string' || !secret.startsWith(API_KEY_PREFIX) || secret.length > 100) return null;
      const hash = digest(secret);
      return all().find((k) => k.digest === hash && live(k)) ?? null;
    },
    list(tenantId) {
      return all().filter((k) => k.tenant_id === tenantId).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).map(view);
    },
    revoke(tenantId, id) {
      const records = all();
      const record = records.find((k) => k.id === id && k.tenant_id === tenantId);
      if (!record) throw fail('not_found');
      if (!record.revoked_at) { record.revoked_at = new Date(now()).toISOString(); store.write('api_keys', records); }
      return view(record);
    },
    // Every live key of a tenant whose allow-list names this hostname (used when it is removed).
    revokeForHostname(tenantId, hostname) {
      const records = all();
      let count = 0;
      for (const k of records) if (k.tenant_id === tenantId && live(k) && k.hostnames?.includes(hostname)) { k.revoked_at = new Date(now()).toISOString(); count++; }
      if (count) store.write('api_keys', records);
      return count;
    },
    // Every live key of a tenant (suspension).
    revokeTenant(tenantId) {
      const records = all();
      let count = 0;
      for (const k of records) if (k.tenant_id === tenantId && live(k)) { k.revoked_at = new Date(now()).toISOString(); count++; }
      if (count) store.write('api_keys', records);
      return count;
    },
    countLive: (tenantId) => all().filter((k) => k.tenant_id === tenantId && live(k)).length,
    touch(id) {
      const records = all();
      const record = records.find((k) => k.id === id);
      // Written at most once a minute per key, so busy keys do not rewrite the file on every call.
      if (record && !(Date.parse(record.last_used_at) > now() - TOUCH_EVERY_MS)) { record.last_used_at = new Date(now()).toISOString(); store.write('api_keys', records); }
    },
    // Audit trail: key id (never the secret), tenant, scope, route template, status, time.
    audit(entry) {
      const log = store.read('api_key_audit', []);
      log.push({ at: new Date(now()).toISOString(), key_id: entry.key_id ?? null, tenant_id: entry.tenant_id ?? null,
        scope: entry.scope ?? null, route: entry.route, method: entry.method, status: entry.status });
      // Drop entries older than 30 days first (Privacy retention), then cap per tenant by count.
      const cutoff = now() - AUDIT_MAX_AGE_DAYS * DAY_MS;
      for (let i = log.length - 1; i >= 0; i--) {
        const t = Date.parse(log[i].at);
        if (!Number.isFinite(t) || t < cutoff) log.splice(i, 1);
      }
      // Capped per tenant, so one tenant's traffic can never push out another tenant's history.
      const mine = log.reduce((n, e) => n + (e.tenant_id === entry.tenant_id), 0);
      if (mine > AUDIT_KEEP_PER_TENANT) log.splice(log.findIndex((e) => e.tenant_id === entry.tenant_id), 1);
      store.write('api_key_audit', log);
    },
    auditFor(tenantId, limit = 50) {
      return store.read('api_key_audit', []).filter((e) => e.tenant_id === tenantId).slice(-limit).reverse()
        .map((e) => ({ at: e.at, key_id: e.key_id, scope: e.scope, route: e.route, method: e.method, status: e.status }));
    },
  };
}
