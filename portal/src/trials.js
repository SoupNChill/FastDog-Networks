// Trial policy (docs/decisions/2026-10-19-trial-pause.md): 7 days from tenant creation, then the edge pauses the
// tenant's hostnames (nothing is deleted) until the plan becomes paid.
// trials.json ({ tenants: { tid: { started_at?, pause_requested_at?, paused_at?, unpaused_at? } } }) is written only by the server sweep.
// trial_overrides.json ({ tenants: { tid: { extra_days?, plan? } } }) is written only by portal/bin/tenant.js; the
// server only reads it. A file with the wrong shape throws, so the sweep takes no action rather than a wrong one.
import { UNPAID_PLANS } from './api-keys.js';
import { createSuspensions } from './suspensions.js';
import { emptyAccounts } from './store.js';

export const TRIAL_DAYS = 7;
export const MAX_EXTRA_DAYS = 365;
const DAY = 86400000;
const AUDIT_KEEP = 5000;
const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const parse = (value) => (typeof value === 'string' ? Date.parse(value) : NaN);
const iso = (ms) => new Date(ms).toISOString();
const normal = (plan) => (typeof plan === 'string' ? plan.trim().toLowerCase() : '');

function readTenants(store, name) {
  const value = store.read(name, { tenants: {} });
  if (!plain(value) || !plain(value.tenants) || !Object.values(value.tenants).every(plain)) throw new Error(`Invalid ${name}.json`);
  return value;
}
export const readOverrides = (store) => readTenants(store, 'trial_overrides');
export const readTrials = (store) => readTenants(store, 'trials');
const own = (all, tid) => (Object.hasOwn(all.tenants, tid) ? all.tenants[tid] : null);

export const isTrialPlan = (plan) => normal(plan) === 'trial';
export const isPaidPlan = (plan) => normal(plan) !== '' && !UNPAID_PLANS.has(normal(plan));
// Overrides may only upgrade: a paid plan in accounts.json wins over any override plan.
export const effectivePlan = (tenant, override) => (!isPaidPlan(tenant?.plan) && typeof override?.plan === 'string' && override.plan.trim() ? override.plan : tenant?.plan);
const extraDays = (override) => (Number.isInteger(override?.extra_days) && override.extra_days > 0 ? Math.min(override.extra_days, MAX_EXTRA_DAYS) : 0);

// Pure: trial details for a tenant whose effective plan is trial, else null. now is in ms.
export function trialInfo(tenant, state, override, now) {
  if (!tenant || !isTrialPlan(effectivePlan(tenant, override))) return null;
  const start = [parse(tenant.created_at), parse(state?.started_at)].find(Number.isFinite);
  if (start === undefined) return null;
  const ends = start + (TRIAL_DAYS + extraDays(override)) * DAY;
  return { active: now < ends, started_at: iso(start), ends_at: iso(ends), days_left: Math.max(0, Math.ceil((ends - now) / DAY)), paused: Boolean(state?.paused_at) };
}

// What the tenant's own pages and hostname creation see: effective plan, its hostname limit and trial details.
// Fail-safe: an unreadable or wrongly shaped trial file counts as absent, so paid tenants keep working.
export function tenantPlan(store, tenant, now) {
  const safe = (read) => { try { return own(read(store), tenant.id); } catch { return null; } };
  const override = safe(readOverrides);
  const plan = effectivePlan(tenant, override);
  return { plan, hostname_limit: isTrialPlan(plan) ? Math.min(tenant.hostname_limit, 1) : tenant.hostname_limit,
    trial: trialInfo(tenant, safe(readTrials), override, now) };
}

// CLI only (portal/bin/tenant.js, under its lock).
export function writeOverride(store, tid, patch) {
  const all = readOverrides(store);
  all.tenants[tid] = { ...own(all, tid), ...patch };
  store.write('trial_overrides', all);
  return all.tenants[tid];
}

// Server sweep only.
function record(store, tid, patch, drop = []) {
  const all = readTrials(store);
  const entry = { ...own(all, tid), ...patch };
  for (const key of drop) delete entry[key];
  all.tenants[tid] = entry;
  store.write('trials', all);
  return entry;
}
function audit(store, entry) {
  const log = store.read('trial_audit', []);
  const entries = Array.isArray(log) ? log : [];
  entries.push(entry);
  store.write('trial_audit', entries.slice(-AUDIT_KEEP));
}

// Idempotent. Pauses trials that have ended and unpauses paused tenants that became paid (or were extended).
// Never deletes, releases or suspends anything; an edge failure retains the pause request for the next run.
export async function sweepTrials({ store, edge, now = Date.now, logger, notify = () => {} }) {
  const log = (entry) => { try { logger?.({ event: 'trial_sweep', ...entry }); } catch { /* Logging cannot affect the sweep. */ } };
  // Owner mail for a newly recorded pause only; it cannot affect the sweep.
  const paused = (accounts, tid, at) => {
    try {
      const user = Array.isArray(accounts.users) ? accounts.users.find((u) => u?.tenant_id === tid) : null;
      notify({ type: 'trial_pause', tenant_id: tid, paused_at: at, ...(typeof user?.email === 'string' ? { email: user.email } : {}) });
    } catch { /* ignore */ }
  };
  const summary = { paused: 0, unpaused: 0, failed: 0 };
  let accounts, overrides, suspensions;
  try {
    accounts = store.read('accounts', emptyAccounts());
    overrides = readOverrides(store);
    readTrials(store);
    suspensions = createSuspensions(store);
  } catch { log({ result: 'skipped', reason: 'state_unreadable' }); return summary; }
  for (const tenant of Array.isArray(accounts.tenants) ? accounts.tenants : []) {
    try {
      if (typeof tenant?.id !== 'string' || suspensions.has(tenant.id)) continue;
      const override = own(overrides, tenant.id);
      const plan = effectivePlan(tenant, override);
      let entry = own(readTrials(store), tenant.id);
      // Legacy trial tenants without created_at get a full trial from the first time the sweep sees them.
      if (isTrialPlan(plan) && !Number.isFinite(parse(tenant.created_at)) && !Number.isFinite(parse(entry?.started_at))) {
        entry = record(store, tenant.id, { started_at: iso(now()) });
      }
      // Re-read immediately before deciding on an edge call: a plan/extension may have changed mid-sweep.
      const freshAccounts = store.read('accounts', emptyAccounts());
      if (!plain(freshAccounts) || !Array.isArray(freshAccounts.tenants)) continue;
      const freshTenant = freshAccounts.tenants.find((item) => item?.id === tenant.id);
      const freshOverride = own(readOverrides(store), tenant.id);
      if (!plain(freshTenant) || typeof freshTenant.plan !== 'string' || !freshTenant.plan.trim()
        || (freshTenant.created_at != null && !Number.isFinite(parse(freshTenant.created_at)))
        || (freshOverride?.plan != null && (typeof freshOverride.plan !== 'string' || !freshOverride.plan.trim()))
        || (freshOverride?.extra_days != null && (!Number.isInteger(freshOverride.extra_days) || freshOverride.extra_days < 0))) continue;
      const freshPlan = effectivePlan(freshTenant, freshOverride);
      const info = trialInfo(freshTenant, entry, freshOverride, now());
      const action = info && !info.active ? 'trial_pause'
        : (entry?.paused_at || entry?.pause_requested_at) && (isPaidPlan(freshPlan) || info?.active) ? 'trial_unpause' : null;
      if (!action) continue;
      const reassert = action === 'trial_pause' && Boolean(entry?.paused_at);
      if (action === 'trial_pause' && !reassert) record(store, tenant.id, { pause_requested_at: iso(now()) });
      let ok = true;
      try { await (action === 'trial_pause' ? edge.pauseTenant(tenant.id) : edge.unpauseTenant(tenant.id)); }
      catch { ok = false; }
      // The CLI can unpause without clearing paused_at; reconcile quietly on every expired sweep.
      if (ok && reassert) continue;
      const at = iso(now());
      if (ok && action === 'trial_pause') { record(store, tenant.id, { paused_at: at }); summary.paused++; paused(freshAccounts, tenant.id, at); }
      else if (ok) { record(store, tenant.id, { unpaused_at: at }, ['paused_at', 'pause_requested_at']); summary.unpaused++; }
      else { summary.failed++; log({ action, result: 'failed', reason: 'edge_failed' }); }
      audit(store, { at, action, tenant_id: tenant.id, edge: ok ? 'ok' : 'failed' });
    } catch { summary.failed++; log({ result: 'failed', reason: 'tenant_error' }); }
  }
  if (summary.paused || summary.unpaused || summary.failed) log({ result: 'done', ...summary });
  return summary;
}

// First run after delayMs, then every intervalMs; runs never overlap. Timers do not keep the process alive.
export function scheduleTrialSweep({ store, edge, logger, notify, now = Date.now, delayMs = 60000, intervalMs = 3600000 }) {
  let running = null;
  let interval = null;
  const run = () => {
    if (!running) running = sweepTrials({ store, edge, now, logger, notify }).catch(() => null).finally(() => { running = null; });
    return running;
  };
  const first = setTimeout(() => { run(); interval = setInterval(run, intervalMs); interval.unref(); }, delayMs);
  first.unref();
  return { run, stop() { clearTimeout(first); clearInterval(interval); } };
}
