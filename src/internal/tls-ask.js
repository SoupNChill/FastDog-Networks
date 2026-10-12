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
    let host;
    try { host = normalizeHostname(input); } catch { return { status: 404 }; }
    if (isReserved(host, reserved) || targets.some((target) => host === target.toLowerCase().replace(/\.$/, ''))) return { status: 404 };
    const claims = readJson('tenant_hostnames.json', [], directory).filter((c) => c.hostname === host);
    const attachments = readJson('attached_hosts.json', [], directory).filter((c) => c.hostname === host);
    // Count active records before validating them: an invalid competing owner is
    // still ambiguous. Legacy records must never coexist with tenant claims.
    if (claims.length && attachments.some((c) => !c.tenant_id)) return { status: 404 };
    const active = [...claims, ...attachments].filter((c) => c.status === 'active');
    if (active.length !== 1) return { status: 404 };
    const owner = active[0];
    const approved = claims.includes(owner)
      ? /^t_[a-z2-7]{20}$/.test(owner.tenant_id) && Number.isFinite(Date.parse(owner.verified_at))
      : !owner.tenant_id;
    if (!approved) return { status: 404 };
    // Unknown and denied SNI must not exhaust Caddy's shared loopback budget.
    const time = now();
    if (time >= until) { until = time + 60000; total = 0; clients.clear(); }
    const count = clients.get(client) ?? 0;
    if (total >= 300 || count >= 30) {
      return { status: 429, retry_after: Math.ceil((until - time) / 1000) };
    }
    total++;
    clients.set(client, count + 1);
    return { status: 200 };
  };
}
