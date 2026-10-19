// Agent bootstrap issuance (PORTAL_AGENT_BOOTSTRAP_ENABLED=1 only; docs/AGENT_BOOTSTRAP_IMPL.md, milestone 4).
// An authenticated session, a scoped API key or an fdct_ connect token may request a one-time fdab_ code for a hostname
// its tenant owns. The edge issues it (internal POST /bootstraps); the portal returns it once and never stores it.
// The portal keeps only nonsecret issuance records (IDs, issuer kind, times, state) for status, cancellation and the
// cancel-by-reissue limits. The edge later asks the issuer-check listener whether the issuer is still eligible.
import { randomUUID, createHash } from 'node:crypto';
import { emptyAccounts } from './store.js';
import { createSessions } from './sessions.js';
import { createSuspensions, effectiveTenant } from './suspensions.js';
import { planAllowsKeys } from './api-keys.js';
import { fail } from './errors.js';

const DAY = 86400000;
// Code TTL (15 min) plus the longest candidate hold (1 h): after this an issuance can no longer authorize anything.
export const ISSUANCE_HORIZON_MS = 75 * 60000;
const KEEP_PER_HOST = 20;

// Nonsecret, stable ID for a session issuer: derived from the stored session hash, never the cookie value.
export const sessionIssuerId = (session) => createHash('sha256').update(`fastdog-session-issuer:${session.token_hash}`).digest('hex').slice(0, 32);

// Issuer eligibility for the issuer-check listener: tenant active and not suspended (nor issued before a suspension),
// issuing user verified with the same authorization generation, and the issuer itself still live.
export function createIssuerValidator({ store, now = Date.now }) {
  const sessions = createSessions(store, now);
  const suspensions = createSuspensions(store);
  const time = (value) => (typeof value === 'number' ? value : Date.parse(value));
  return ({ issuer_kind: kind, issuer_id: id, authorization_generation: generation }) => {
    const accounts = store.read('accounts', emptyAccounts());
    const tenantOk = (tid, issuedAt) => {
      const tenant = effectiveTenant(accounts.tenants.find((t) => t.id === tid), suspensions);
      return Boolean(tenant) && tenant.status === 'active' && !suspensions.stale(tid, issuedAt) ? tenant : null;
    };
    const userOk = (userId, tid, version) => {
      const user = accounts.users.find((u) => u.id === userId && u.tenant_id === tid);
      return Boolean(user && user.email_verified_at && (user.auth_version ?? null) === version);
    };
    if (kind === 'session') {
      const session = sessions.active().find((s) => s.user_id && sessionIssuerId(s) === id);
      const user = session && accounts.users.find((u) => u.id === session.user_id);
      return Boolean(user && session.auth_version === user.auth_version && generation === user.auth_version &&
        tenantOk(user.tenant_id, session.created_at) && userOk(user.id, user.tenant_id, session.auth_version));
    }
    if (kind === 'api_key') {
      const key = store.read('api_keys', []).find((k) => k.id === id);
      if (!key || key.revoked_at || !(time(key.expires_at) > now()) || !key.scopes?.includes('connect') || (key.auth_version ?? 0) !== generation) return false;
      return planAllowsKeys(tenantOk(key.tenant_id, key.created_at)) && userOk(key.user_id, key.tenant_id, key.auth_version ?? null);
    }
    if (kind === 'connect_token') {
      // A used (command-issued) token is expected; a revoked, expired or reset one is not.
      const token = store.read('connect_tokens', []).find((t) => t.id === id);
      if (!token || token.revoked_at || !(time(token.expires_at) > now()) || (token.auth_version ?? 0) !== generation) return false;
      return Boolean(tenantOk(token.tenant_id, token.created_at)) && userOk(token.user_id, token.tenant_id, token.auth_version ?? null);
    }
    return false;
  };
}

// Edge errors the portal treats as definitive refusals: nothing was committed, so a token reservation may be released.
const DEFINITIVE = new Set(['hostname_not_found', 'not_active', 'rate_limited', 'not_found', 'invalid_tenant', 'invalid_hostname', 'unauthorized',
  'administratively_suspended', 'agent_bootstrap_unavailable']);

export function createAgentBootstrap({ store, edge, limits, now = Date.now }) {
  const all = () => store.read('agent_bootstraps', []).filter((r) => Date.parse(r.created_at) > now() - DAY);
  const save = (records) => store.write('agent_bootstraps', records);
  const update = (id, patch) => { const records = all(); const r = records.find((x) => x.issuance_id === id); if (r) { Object.assign(r, patch); save(records); } };
  // Records are append-only, so newest first is reverse insertion order (timestamps may tie).
  const mine = (tid, host) => all().filter((r) => r.tenant_id === tid && r.hostname === host).reverse();
  const view = (r) => ({ issuance_id: r.issuance_id, issuer_kind: r.issuer_kind, deployment_id: r.deployment_id, created_at: r.created_at,
    expires_at: r.expires_at ?? null, state: r.state });
  // The newest issuance that may still authorize something at the edge.
  const live = (tid, host) => mine(tid, host).find((r) => r.state === 'issued' && Date.parse(r.created_at) > now() - ISSUANCE_HORIZON_MS);
  function markCancelled(tid, host) {
    const records = all(); let changed = false;
    for (const r of records) if (r.tenant_id === tid && r.hostname === host && r.state === 'issued') { r.state = 'cancelled'; changed = true; }
    if (changed) save(records);
  }
  return {
    // `issuer` {kind,id,authorization_generation}; `principal` is the human behind it (cancel-by-reissue limits);
    // `charge()` takes the caller's existing command budgets (it runs only after the reissue limits pass).
    async issue({ tid, hostname, origin, issuer, principal, charge = () => {}, unsuspended = (t) => t }) {
      const claim = await edge.getHostname(tid, hostname);
      if (claim.status !== 'active') throw fail('not_active');
      // Cancel-by-reissue: 3/hour and 6/day per principal across hostnames, refused before any edge mutation.
      const previous = live(tid, hostname);
      if (previous && Date.parse(previous.expires_at) > now()) {
        let status = 'pending';
        try { status = (await edge.getBootstrap(tid, hostname, previous.issuance_id)).status; } catch { /* Uncertain counts as pending. */ }
        if (status === 'pending') {
          limits.take(`bootstrap-reissue-hour:${principal}`, 3, 3600000, true);
          try { limits.take(`bootstrap-reissue-day:${principal}`, 6, DAY, true); }
          catch (error) { limits.refund(`bootstrap-reissue-hour:${principal}`, true); throw error; }
        }
      }
      charge();
      const record = { issuance_id: randomUUID(), deployment_id: randomUUID(), tenant_id: tid, hostname, issuer_kind: issuer.kind,
        issuer_id: issuer.id, principal, created_at: new Date(now()).toISOString(), state: 'requested' };
      const records = [...all(), record];
      // Bounded per hostname (the edge allows at most 8 issuances a day, so live records are never dropped).
      const drop = new Set(records.filter((r) => r.tenant_id === tid && r.hostname === hostname).reverse().slice(KEEP_PER_HOST));
      save(records.filter((r) => !drop.has(r)));
      let issued;
      try {
        issued = await edge.issueBootstrap(unsuspended(tid), hostname, { origin, deployment_id: record.deployment_id, issuance_id: record.issuance_id, issuer });
      } catch (error) {
        if (DEFINITIVE.has(error.code)) { update(record.issuance_id, { state: 'failed' }); throw error; }
        // Outcome unknown: the raw code is unrecoverable, so look the issuance up and revoke an orphan. Never retry.
        let state = 'uncertain';
        try {
          await edge.getBootstrap(tid, hostname, record.issuance_id);
          await edge.cancelBootstraps(tid, hostname);
          state = 'orphan_cancelled';
        } catch (lookup) { if (lookup.code === 'agent_bootstrap_not_found') state = 'failed'; }
        update(record.issuance_id, { state });
        // An issuance that may have committed keeps the caller's reservation (a used token is not revived).
        throw Object.assign(error, { uncertain: state !== 'failed' });
      }
      update(record.issuance_id, { state: 'issued', expires_at: issued.expires_at });
      return { issuance_id: record.issuance_id, code: issued.code, hostname, origin: issued.origin, deployment_id: record.deployment_id, expires_at: issued.expires_at };
    },
    async list(tid, hostname) {
      await edge.getHostname(tid, hostname);
      const records = mine(tid, hostname).slice(0, 10).map(view);
      const latest = records.find((r) => r.state === 'issued');
      if (latest) {
        try { latest.status = (await edge.getBootstrap(tid, hostname, latest.issuance_id)).status; } catch { latest.status = 'unknown'; }
      }
      return { bootstraps: records };
    },
    async cancel(tid, hostname) {
      const result = await edge.cancelBootstraps(tid, hostname);
      markCancelled(tid, hostname);
      return { cancelled: Boolean(result.cancelled) };
    },
    // Explicit owner action: revoke the current credentials, pending codes and candidates; nothing is minted.
    async revokeAgent(tid, hostname) {
      await edge.revokeAgent(tid, hostname);
      markCancelled(tid, hostname);
      return { hostname, revoked: true };
    },
    async confirm(tid, hostname, credentialId, keyFingerprint) {
      return edge.confirmCandidate(tid, hostname, credentialId, keyFingerprint);
    },
    // Connect-token revocation: the newest live issuance is the only one the edge still honours, so cancelling the
    // claim's bootstraps cancels exactly a revoked token's pending code, recovery and candidates. Active agents stay.
    async cancelForConnectTokens(tid, hostname) {
      const latest = live(tid, hostname);
      if (!latest || latest.issuer_kind !== 'connect_token') return false;
      await edge.cancelBootstraps(tid, hostname);
      markCancelled(tid, hostname);
      return true;
    },
  };
}
