import { normalizeHostname, isReserved } from '../onboard/hostname.js';
import fs from 'node:fs';
import path from 'node:path';
import { readJson, dataDir, jsonRevision } from '../onboard/json.js';
import { reservedSuffixes } from '../lib/config.js';
import { attachTarget, altAttachTarget } from '../onboard/attach.js';

// Local writes invalidate immediately; external store changes are checked at most once per second.
export function createTlsAsk(opts = {}) {
  const enabled = opts.tlsAskEnabled ?? (process.env.TLS_ASK_ENABLED === '1');
  const directory = opts.dataDir ?? dataDir();
  const now = opts.now ?? Date.now;
  const targets = [opts.attachTarget ?? attachTarget(), opts.altAttachTarget ?? altAttachTarget()].filter(Boolean);
  const reserved = opts.reservedSuffixes ?? reservedSuffixes(...targets);
  let until = 0;
  let total = 0;
  const names = new Map();
  const files = ['tenant_hostnames.json', 'attached_hosts.json'];
  let owners = new Map();
  let revisions;
  let stamps;
  let nextCheck = 0;
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
      if (claimSet.has(owner)
        ? /^t_[a-z2-7]{20}$/.test(owner.tenant_id) && Number.isFinite(Date.parse(owner.verified_at))
        : !owner.tenant_id) index.set(host, owner);
    }
    owners = index;
    revisions = current;
    stamps = updated;
  }
  return (input) => {
    if (!enabled) return { status: 404 };
    let host;
    try { host = normalizeHostname(input); } catch { /* Invalid names share a budget. */ }
    const time = now();
    if (host && !isReserved(host, reserved) && !targets.some((target) => host === target.toLowerCase().replace(/\.$/, ''))) {
      refresh(time);
      // Approved owners never spend or wait on anonymous deny budgets.
      if (owners.has(host)) return { status: 200 };
    }
    if (time >= until) { until = time + 60000; total = 0; names.clear(); }
    const nameCount = names.get(host) ?? 0;
    // Count every denied ask globally, including asks limited by the per-name budget.
    const globalLimited = total >= 300;
    if (!globalLimited) total++;
    if (globalLimited || nameCount >= 30) {
      return { status: 429, retry_after: Math.ceil((until - time) / 1000) };
    }
    names.set(host, nameCount + 1);
    return { status: 404 };
  };
}
