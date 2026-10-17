import { normalizeHostname, isReserved } from '../onboard/hostname.js';
import fs from 'node:fs';
import path from 'node:path';
import { readJson, dataDir, jsonRevision } from '../onboard/json.js';
import { reservedSuffixes } from '../lib/config.js';
import { attachTarget, altAttachTarget } from '../onboard/attach.js';
import { isTestLabelHost, isGuardrailHost, testTenants } from './test-labels.js';
import { checkClaimProof } from './claims.js';
import { edgeIp } from '../onboard/store.js';
import dns from 'node:dns/promises';
import { STATE_FILE, validApproval, updateApprovals } from './tls-approval-state.js';

const HOUR = 3600000;
const MINUTE = 60000;
const WEEK = 7 * 24 * HOUR;
const positive = (value, fallback) => {
  const number = Number(value);
  return value !== undefined && value !== '' && Number.isSafeInteger(number) && number > 0 ? number : fallback;
};
// Common second-level public suffixes under a two-letter TLD (x.example.co.uk -> example.co.uk).
const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'me', 'ltd', 'ne', 'or', 'go', 'id', 'gob']);
export function registeredDomain(host) {
  const labels = host.split('.');
  const keep = labels.length > 2 && labels.at(-1).length === 2 && SECOND_LEVEL.has(labels.at(-2)) ? 3 : 2;
  return labels.slice(-keep).join('.');
}

// Approvals spend an issuance budget; denies are cached; anonymous checks have their own cap.
// Local writes invalidate immediately; external store changes are checked at most once per second.
// A first approval of a tenant claim re-confirms its DNS proof live, so the result is a decision, or a
// Promise of one when that lookup is needed. Static hosts and legacy attachments have no proof to re-check.
export function createTlsAsk(opts = {}) {
  const env = process.env;
  const enabled = opts.tlsAskEnabled ?? (env.TLS_ASK_ENABLED === '1');
  const directory = opts.dataDir ?? dataDir();
  const now = opts.now ?? Date.now;
  const primary = opts.attachTarget ?? attachTarget();
  const alt = opts.altAttachTarget ?? altAttachTarget();
  const targets = [primary, alt].filter(Boolean);
  const reserved = opts.reservedSuffixes ?? reservedSuffixes(...targets);
  const tenantMax = positive(opts.tenantMaxPerHour ?? env.TLS_ASK_TENANT_MAX_PER_HOUR, 10);
  const globalMax = positive(opts.globalMaxPerHour ?? env.TLS_ASK_GLOBAL_MAX_PER_HOUR, 60);
  const reserveValue = Number(opts.globalReserve ?? env.TLS_ASK_GLOBAL_RESERVE ?? 20);
  const globalReserve = Math.min(globalMax, Number.isSafeInteger(reserveValue) && reserveValue >= 0 ? reserveValue : 20);
  const domainMax = positive(opts.domainMaxPerHour ?? env.TLS_ASK_DOMAIN_MAX_PER_HOUR, 5);
  // Conservative weekly guard per tenant/domain, or globally for static/legacy hosts.
  const domainWeekMax = positive(opts.domainMaxPerWeek ?? env.TLS_ASK_DOMAIN_WEEK_MAX, 40);
  const hostDayMax = positive(opts.hostDayMax ?? env.TLS_ASK_HOST_DAY_MAX, 3);
  const hostWeekMax = positive(opts.hostWeekMax ?? env.TLS_ASK_HOST_WEEK_MAX, 5);
  let lastGlobalWarning = -Infinity;
  const liveVerify = opts.liveVerify ?? (env.TLS_ASK_LIVE_VERIFY !== '0');
  const resolver = opts.resolver ?? dns;
  const liveTimeout = positive(opts.liveVerifyTimeoutMs, 3000);
  const livePositiveTtl = positive(opts.liveVerifyPositiveTtlMs, 10 * MINUTE);
  const liveNegativeTtl = positive(opts.liveVerifyNegativeTtlMs, 60000);
  const liveUnavailableTtl = positive(opts.liveVerifyUnavailableTtlMs, 10000);
  const checksMax = positive(opts.checksPerMinute ?? env.TLS_ASK_CHECKS_PER_MINUTE, 600);
  const denyTtl = positive(opts.denyTtlMs, MINUTE);
  const denyMax = positive(opts.denyCacheMax, 10000);
  // Explicit operator list of existing static hosts; the only way a reserved name is approved.
  const statics = new Set();
  for (const entry of opts.staticHosts ?? (env.TLS_ASK_STATIC_HOSTS ?? '').split(',')) {
    try { if (entry.trim()) statics.add(normalizeHostname(entry)); } catch { /* Ignore malformed entries. */ }
  }
  const files = ['tenant_hostnames.json', 'attached_hosts.json'];
  const targetNames = targets.map((target) => target.toLowerCase().replace(/\.$/, ''));
  let owners = new Map(); // host -> tenant id, or null for a legacy attachment
  let proofs = new Map(); // host -> challenge TXT value of the verified claim (claims only)
  const live = new Map(); // host -> { proof, ok, until }; insertion order is chronological
  const inflight = new Map(); // host:proof -> Promise of a live result
  let revisions;
  let stamps;
  let nextCheck = 0;
  let failedUntil = 0;
  const approvals = new Map(); // host -> { tenant, at }; insertion order is chronological
  let history = []; // { host, tenant, domain, at } for the last 7 days; persisted across restarts
  let stateFullUntil = 0; // an unreadable state file counts every window as full for a while
  const stateFile = path.join(directory, STATE_FILE);
  const denies = new Map(); // host -> expiry; insertion order is chronological
  let checkUntil = 0;
  let checkCount = 0;
  const counts = {};

  let stateStamp;
  let nextStateCheck = now() + 10000;
  let saveFailed = false;
  let lastStateWarning = -Infinity;
  function stamp() {
    try { const st = fs.statSync(stateFile); return `${st.mtimeMs}:${st.ino}`; }
    catch (error) { if (error.code === 'ENOENT') return 'missing'; throw error; }
  }
  function refreshState(time) {
    if (time < nextStateCheck) return;
    nextStateCheck = time + 10000;
    const updated = stamp();
    if (updated !== stateStamp) loadState(updated);
  }
  function loadState(updated) {
    if (!enabled) return;
    const time = now();
    approvals.clear();
    history = [];
    try {
      stateStamp = updated ?? stamp();
      const list = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      if (!Array.isArray(list) || !list.every(validApproval)) throw new Error('malformed');
      history = list.filter((e) => time - e.at < WEEK).map(({ host, tenant, domain, at }) => ({ host, tenant, domain, at }))
        .sort((a, b) => a.at - b.at);
      for (const entry of history) {
        if (time - entry.at >= HOUR) continue;
        approvals.delete(entry.host);
        approvals.set(entry.host, { tenant: entry.tenant, domain: entry.domain, at: entry.at });
      }
    } catch (error) {
      if (error.code === 'ENOENT') return;
      try {
        fs.renameSync(stateFile, `${stateFile}.corrupt-${time}`);
      } catch {
        console.error('tls ask: could not quarantine approval state; refusing approvals until restart');
        stateFullUntil = Infinity;
        return;
      }
      console.error('tls ask: approval state quarantined as .corrupt-<timestamp>; approvals paused for 10 minutes, then starting empty history automatically; operator should inspect the quarantined file');
      stateFullUntil = time + 10 * MINUTE;
    }
  }
  function saveState(entry) {
    try {
      history = updateApprovals(directory, list => [
        ...list.filter(e => now() - e.at < WEEK), ...(entry ? [entry] : []),
      ]);
      // Do not advance the observed stamp here: an operator reset may have occurred
      // since our last reload, and the next periodic check must clear stale repeats.
      saveFailed = false;
      return true;
    } catch {
      saveFailed = true;
      if (now() - lastStateWarning >= 5 * MINUTE) {
        console.error('tls ask: could not persist approval state');
        lastStateWarning = now();
      }
      return false;
    }
  }
  loadState();

  function refresh(time) {
    const current = files.map((file) => jsonRevision(file, directory)).join(':');
    if (current === revisions && time < nextCheck) return;
    nextCheck = time + 1000;
    const updated = files.map((file) => {
      try {
        const stat = fs.statSync(path.join(directory, file));
        return `${stat.mtimeMs}:${stat.ctimeMs}:${stat.size}:${stat.ino}`;
      } catch (error) {
        if (error.code === 'ENOENT') return 'missing';
        throw error;
      }
    }).join('|');
    if (current === revisions && updated === stamps) return;
    const [claims, attachments] = files.map((file) => readJson(file, [], directory));
    const grouped = new Map();
    for (const record of [...claims, ...attachments]) {
      const group = grouped.get(record.hostname) ?? [];
      group.push(record);
      grouped.set(record.hostname, group);
    }
    const claimSet = new Set(claims);
    const index = new Map();
    const proofIndex = new Map();
    for (const [host, records] of grouped) {
      if (records.some((c) => claimSet.has(c) && c.status === 'active') && records.some((c) => !claimSet.has(c) && !c.tenant_id)) continue;
      const active = records.filter((c) => c.status === 'active');
      if (active.length !== 1) continue;
      const owner = active[0];
      if (claimSet.has(owner)) {
        if (typeof owner.txt_value === 'string' && owner.txt_value.trim() && /^t_[a-z2-7]{20}$/.test(owner.tenant_id) && Number.isFinite(Date.parse(owner.verified_at))) {
          index.set(host, owner.tenant_id);
          proofIndex.set(host, owner.txt_value);
        }
      } else if (!owner.tenant_id) index.set(host, null);
    }
    owners = index;
    proofs = proofIndex;
    denies.clear(); // A claim that just became verified must not wait out a cached deny.
    revisions = current;
    stamps = updated;
  }

  const decide = (status, reason, extra) => {
    counts[reason] = (counts[reason] ?? 0) + 1;
    return { status, reason, ...extra };
  };
  const seconds = (ms) => Math.max(1, Math.ceil(ms / 1000));

  function approve(host, tenant, time) {
    for (const [name, entry] of approvals) {
      if (time - entry.at < HOUR) break;
      approvals.delete(name);
    }
    const prior = approvals.get(host);
    // Re-approvals within the window are free, even when a cap has since been reached.
    if (prior && prior.tenant === tenant) return decide(200, 'approved_repeat');
    if (prior) approvals.delete(host);
    if (time < stateFullUntil) return decide(429, 'approval_state_unavailable', { retry_after: Number.isFinite(stateFullUntil) ? seconds(stateFullUntil - time) : 600 });
    if (saveFailed && !saveState()) return decide(429, 'approval_state_unavailable', { retry_after: 10 });
    history = history.filter((entry) => time - entry.at < WEEK);
    const day = history.filter((entry) => entry.host === host && time - entry.at < 24 * HOUR);
    if (day.length >= hostDayMax) return decide(429, 'approval_cap_host_day', { retry_after: seconds(day[0].at + 24 * HOUR - time) });
    const hostWeek = history.filter((entry) => entry.host === host);
    if (hostWeek.length >= hostWeekMax) return decide(429, 'approval_cap_host_week', { retry_after: seconds(hostWeek[0].at + WEEK - time) });
    const global = history.filter((entry) => time - entry.at < HOUR);
    const reserveEligible = statics.has(host) || (tenant && !global.some(entry => entry.tenant === tenant));
    if (global.length >= (reserveEligible ? globalMax : globalMax - globalReserve)) {
      if (time - lastGlobalWarning >= 5 * MINUTE) {
        console.warn('tls ask: approval_cap_global');
        lastGlobalWarning = time;
      }
      return decide(429, 'approval_cap_global', { retry_after: global.length ? seconds(global[0].at + HOUR - time) : 3600 });
    }
    if (tenant) {
      const mine = [...approvals.values()].filter((entry) => entry.tenant === tenant);
      if (mine.length >= tenantMax) return decide(429, 'approval_cap_tenant', { retry_after: seconds(mine[0].at + HOUR - time) });
    }
    const domain = registeredDomain(host);
    const same = [...approvals.values()].filter((entry) => entry.domain === domain && entry.tenant === tenant);
    if (same.length >= domainMax) return decide(429, 'approval_cap_domain', { retry_after: seconds(same[0].at + HOUR - time) });
    const week = history.filter((entry) => entry.domain === domain && entry.tenant === tenant);
    if (week.length >= domainWeekMax) return decide(429, 'approval_cap_domain_week', { retry_after: seconds(week[0].at + WEEK - time) });
    if (!saveState({ host, tenant, domain, at: time })) return decide(429, 'approval_state_unavailable', { retry_after: 10 });
    approvals.set(host, { tenant, domain, at: time });
    return decide(200, 'approved_new');
  }

  // Resolves to true (proof present), false (proof gone) or null (lookup failed or timed out).
  function liveCheck(host, proof, time) {
    const cached = live.get(host);
    if (cached && cached.proof === proof && cached.until > time) return cached.ok;
    const key = `${host}\n${proof}`;
    if (!inflight.has(key)) {
      const lookup = checkClaimProof(host, proof, { resolver, attachTarget: primary, altAttachTarget: alt,
        edgePublicIp: opts.edgePublicIp ?? edgeIp(), timeout: liveTimeout });
      inflight.set(key, lookup.then(({ routing, ownership }) => {
        if ([routing, ownership].some((check) => check.error === 'dns_timeout')) return null;
        return routing.ok && ownership.ok;
      }, () => null).then((ok) => {
        inflight.delete(key);
        live.delete(host);
        if (live.size >= denyMax) live.delete(live.keys().next().value);
        // Failed lookups are cached briefly too, so a DNS outage is not hammered by every Caddy retry.
        live.set(host, { proof, ok, until: now() + (ok === null ? liveUnavailableTtl : ok ? livePositiveTtl : liveNegativeTtl) });
        return ok;
      }));
    }
    return inflight.get(key);
  }

  // First approvals of a claim re-confirm its DNS proof before any budget is spent.
  async function approveLive(host, tenant, proof) {
    const ok = await liveCheck(host, proof, now());
    if (ok === null) return decide(503, 'live_verify_unavailable');
    if (!ok) return decide(404, 'live_verify_failed');
    const time = now();
    try { refresh(time); } catch { return decide(404, 'store_error'); }
    // The claim may have been revoked or replaced while DNS was being queried.
    if (owners.get(host) !== tenant || proofs.get(host) !== proof) return decide(404, 'denied');
    return approve(host, tenant, time);
  }

  function deny(host, reason, time) {
    for (const [name, expiry] of denies) {
      if (expiry > time) break;
      denies.delete(name);
    }
    if (host) {
      if (denies.size >= denyMax) denies.delete(denies.keys().next().value);
      denies.set(host, time + denyTtl);
    }
    return decide(404, reason);
  }

  const ask = (input) => {
    if (!enabled) return { status: 404 };
    const time = now();
    try {
      if (time < failedUntil) return decide(404, 'store_error');
      try {
        refreshState(time);
        refresh(time);
      } catch {
        // Fail closed, including for previously approved hosts, and retry the stores shortly.
        owners = new Map();
        denies.clear();
        revisions = undefined;
        failedUntil = time + 1000;
        return decide(404, 'store_error');
      }
      let host;
      try { host = normalizeHostname(input); if (host !== input) host = undefined; } catch { /* Invalid names share the check budget. */ }
      let tenant = null;
      let approvable = false;
      if (host && !isGuardrailHost(host)) {
        if (statics.has(host)) approvable = true;
        else if (owners.has(host)) {
          const open = !isReserved(host, reserved) && !targetNames.includes(host);
          // Under the reserved attach domain only a verified claim by a marked test tenant on an e2e label is approvable.
          const label = primary && isTestLabelHost(host, primary, alt);
          if (label ? testTenants(directory).has(owners.get(host)) : open) {
            approvable = true;
            tenant = owners.get(host);
          }
        }
      }
      // Approvable hosts only spend the issuance budget; anonymous checks never do.
      if (approvable) {
        const prior = approvals.get(host);
        const repeat = prior && prior.tenant === tenant && time - prior.at < HOUR;
        // Only otherwise approvable claims reach DNS, and always before a budget slot is charged.
        if (liveVerify && !repeat && !statics.has(host) && proofs.has(host)) {
          return approveLive(host, tenant, proofs.get(host)).catch(() => decide(404, 'error'));
        }
        return approve(host, tenant, time);
      }
      if (host && (denies.get(host) ?? 0) > time) return decide(404, 'denied_cached');
      if (time >= checkUntil) { checkUntil = time + MINUTE; checkCount = 0; }
      if (checkCount >= checksMax) return decide(429, 'check_cap', { retry_after: seconds(checkUntil - time) });
      checkCount++;
      return deny(host, host ? 'denied' : 'invalid', time);
    } catch {
      return decide(404, 'error');
    }
  };
  // Aggregate decision counts only; never hostnames.
  ask.counts = () => ({ ...counts });
  return ask;
}
