import { normalizeHostname, isReserved } from '../onboard/hostname.js';
import fs from 'node:fs';
import path from 'node:path';
import { readJson, dataDir, jsonRevision } from '../onboard/json.js';
import { reservedSuffixes } from '../lib/config.js';
import { attachTarget, altAttachTarget } from '../onboard/attach.js';
import { isTestLabelHost } from './test-labels.js';

const HOUR = 3600000;
const MINUTE = 60000;
const positive = (value, fallback) => {
  const number = Number(value);
  return value !== undefined && value !== '' && Number.isSafeInteger(number) && number > 0 ? number : fallback;
};

// Approvals spend an issuance budget; denies are cached; anonymous checks have their own cap.
// Local writes invalidate immediately; external store changes are checked at most once per second.
export function createTlsAsk(opts = {}) {
  const env = process.env;
  const enabled = opts.tlsAskEnabled ?? (env.TLS_ASK_ENABLED === '1');
  const directory = opts.dataDir ?? dataDir();
  const now = opts.now ?? Date.now;
  const primary = opts.attachTarget ?? attachTarget();
  const alt = opts.altAttachTarget ?? altAttachTarget();
  const targets = [primary, alt].filter(Boolean);
  const reserved = opts.reservedSuffixes ?? reservedSuffixes(...targets);
  const tenantMax = positive(opts.tenantMaxPerHour ?? env.TLS_ASK_TENANT_MAX_PER_HOUR, 20);
  const globalMax = positive(opts.globalMaxPerHour ?? env.TLS_ASK_GLOBAL_MAX_PER_HOUR, 100);
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
  let revisions;
  let stamps;
  let nextCheck = 0;
  let failedUntil = 0;
  const approvals = new Map(); // host -> { tenant, at }; insertion order is chronological
  const denies = new Map(); // host -> expiry; insertion order is chronological
  let checkUntil = 0;
  let checkCount = 0;
  const counts = {};

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
    for (const [host, records] of grouped) {
      if (records.some((c) => claimSet.has(c)) && records.some((c) => !claimSet.has(c) && !c.tenant_id)) continue;
      const active = records.filter((c) => c.status === 'active');
      if (active.length !== 1) continue;
      const owner = active[0];
      if (claimSet.has(owner)) {
        if (/^t_[a-z2-7]{20}$/.test(owner.tenant_id) && Number.isFinite(Date.parse(owner.verified_at))) index.set(host, owner.tenant_id);
      } else if (!owner.tenant_id) index.set(host, null);
    }
    owners = index;
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
    if (approvals.size >= globalMax) {
      return decide(429, 'approval_cap_global', { retry_after: seconds(approvals.values().next().value.at + HOUR - time) });
    }
    if (tenant) {
      const mine = [...approvals.values()].filter((entry) => entry.tenant === tenant);
      if (mine.length >= tenantMax) return decide(429, 'approval_cap_tenant', { retry_after: seconds(mine[0].at + HOUR - time) });
    }
    approvals.set(host, { tenant, at: time });
    return decide(200, 'approved_new');
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
      try { host = normalizeHostname(input); } catch { /* Invalid names share the check budget. */ }
      let tenant = null;
      let approvable = false;
      if (host) {
        if (statics.has(host)) approvable = true;
        else if (owners.has(host)) {
          const open = !isReserved(host, reserved) && !targetNames.includes(host);
          // Under the reserved attach domain only a verified tenant claim on an e2e test label is approvable.
          if (open || (owners.get(host) && primary && isTestLabelHost(host, primary, alt))) {
            approvable = true;
            tenant = owners.get(host);
          }
        }
      }
      // Approvable hosts only spend the issuance budget; anonymous checks never do.
      if (approvable) return approve(host, tenant, time);
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
