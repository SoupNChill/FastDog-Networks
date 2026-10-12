import { normalizeHostname, isReserved } from '../onboard/hostname.js';
import { readJson, dataDir } from '../onboard/json.js';
import { reservedSuffixes } from '../lib/config.js';
import { attachTarget, altAttachTarget } from '../onboard/attach.js';

// Separate from claim lifecycle: authorization reads current storage on every ask.
export function createTlsAsk(opts = {}) {
  const enabled = opts.tlsAskEnabled ?? (process.env.TLS_ASK_ENABLED === '1');
  const directory = opts.dataDir ?? dataDir();
  const now = opts.now ?? Date.now;
  const targets = [opts.attachTarget ?? attachTarget(), opts.altAttachTarget ?? altAttachTarget()].filter(Boolean);
  const reserved = opts.reservedSuffixes ?? reservedSuffixes(...targets);
  let until = 0;
  let total = 0;
  const clients = new Map();
  return (input, client) => {
    if (!enabled) return { status: 404 };
    const time = now();
    if (time >= until) { until = time + 60000; total = 0; clients.clear(); }
    const count = clients.get(client) ?? 0;
    if (total >= 300 || count >= 30) {
      return { status: 429, retry_after: Math.ceil((until - time) / 1000) };
    }
    total++;
    clients.set(client, count + 1);
    let host;
    try { host = normalizeHostname(input); } catch { return { status: 404 }; }
    if (isReserved(host, reserved) || targets.some((target) => host === target.toLowerCase().replace(/\.$/, ''))) return { status: 404 };
    const claims = readJson('tenant_hostnames.json', [], directory);
    const active = claims.some((c) => c.hostname === host && /^t_[a-z2-7]{20}$/.test(c.tenant_id) &&
      c.status === 'active' && Number.isFinite(Date.parse(c.verified_at)));
    const legacy = readJson('attached_hosts.json', [], directory).some((c) =>
      c.hostname === host && !c.tenant_id && c.status === 'active');
    return { status: active || legacy ? 200 : 404 };
  };
}
