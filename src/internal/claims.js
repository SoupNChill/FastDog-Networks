import { randomBytes } from 'node:crypto';
import dns from 'node:dns/promises';
import { readJson, writeJson, dataDir as defaultDataDir } from '../onboard/json.js';
import { issueCredential } from '../onboard/credentials.js';
import { normalizeHostname, isReserved } from '../onboard/hostname.js';
import { checkDnsVerification, attachTarget as defaultTarget, altAttachTarget as defaultAltTarget } from '../onboard/attach.js';
import { edgeIp } from '../onboard/store.js';
import { reservedSuffixes as defaultSuffixes } from '../lib/config.js';

export const fail = (status, code, extra = {}) => Object.assign(new Error(code), { status, code, ...extra });
const DAY = 86400000;

export function createClaims(opts, changed) {
  const directory = opts.dataDir ?? defaultDataDir();
  const now = opts.now ?? Date.now;
  const attachTarget = opts.attachTarget ?? defaultTarget();
  const altAttachTarget = opts.altAttachTarget ?? defaultAltTarget();
  const reserved = opts.reservedSuffixes ?? defaultSuffixes(attachTarget, altAttachTarget);
  const resolver = opts.resolver ?? dns;
  const registry = opts.registry;
  const read = (name) => readJson(name, [], directory);
  const write = (name, data) => writeJson(name, data, 0o600, directory);
  const claims = () => read('tenant_hostnames.json').filter((c) => c.status === 'active' || Date.parse(c.expires_at) > now());
  const save = (records) => write('tenant_hostnames.json', records);
  const legacy = (host) => read('attached_hosts.json').find((c) => c.hostname === host && !c.tenant_id);
  const unavailable = (records, tid, host) => Boolean(legacy(host) || records.some((c) => c.hostname === host && c.status === 'active' && c.tenant_id !== tid));
  const find = (records, tid, host) => {
    const record = records.find((c) => c.tenant_id === tid && c.hostname === host);
    if (!record) throw fail(404, 'hostname_not_found');
    return record;
  };
  const limits = new Map();
  function limit(key, count, window) {
    const time = now();
    for (const [k, value] of limits) if (value.until <= time) limits.delete(k);
    const value = limits.get(key) ?? { count: 0, until: time + window };
    if (value.count >= count) throw fail(429, 'rate_limited', { retry_after: Math.ceil((value.until - time) / 1000) });
    value.count++;
    limits.set(key, value);
  }
  function agent(host) {
    const value = registry?.getAgentByHost(host);
    return { connected: Boolean(value && (value.connected ?? (value.ws?.readyState === 1))),
      last_seen: value?.last_seen ?? value?.lastSeen ?? null,
      registered_at: value?.registered_at ?? value?.registeredAt ?? null };
  }
  function present(c) {
    const record = { hostname: c.hostname, status: c.status, created_at: c.created_at };
    if (c.status === 'active') return { ...record, verified_at: c.verified_at, agent: agent(c.hostname) };
    return { ...record, expires_at: c.expires_at, agent: null, dns: {
      cname: { name: c.hostname, type: 'CNAME', value: attachTarget, ttl: 300 },
      txt: { name: `_fastdog-challenge.${c.hostname}`, type: 'TXT', value: c.txt_value, ttl: 300 },
      apex_note: c.hostname.split('.').length === 2 ? 'Use a subdomain or an ALIAS/ANAME record if your DNS provider supports it; standard DNS does not allow a CNAME at the apex.' : null,
    } };
  }
  function active(c) { if (c.status !== 'active') throw fail(409, 'not_active'); }
  function revoke(tid, host) {
    const credentials = read('agent-credentials.json');
    for (const c of credentials) if (c.tenant_id === tid && c.claim_hostname === host && !c.revoked_at) c.revoked_at = new Date(now()).toISOString();
    write('agent-credentials.json', credentials);
  }
  async function timed(fn) {
    let timer;
    try {
      return await Promise.race([Promise.resolve().then(fn), new Promise((_, reject) => {
        timer = setTimeout(() => reject(fail(200, 'dns_timeout')), 3500);
      })]);
    } finally { clearTimeout(timer); }
  }
  return {
    list(tid) { return { hostnames: claims().filter((c) => c.tenant_id === tid).sort((a, b) => a.created_at.localeCompare(b.created_at)).map(present) }; },
    get(tid, host) { return present(find(claims(), tid, host)); },
    create(tid, body) {
      const host = normalizeHostname(body.hostname);
      if (isReserved(host, reserved) || [attachTarget, altAttachTarget].filter(Boolean).some((target) => host === target.toLowerCase().replace(/\.$/, ''))) throw fail(400, 'reserved_hostname');
      if (!Number.isInteger(body.hostname_limit) || body.hostname_limit < 1 || body.hostname_limit > 1000) throw fail(400, 'invalid_limit');
      const records = claims();
      if (unavailable(records, tid, host)) throw fail(409, 'hostname_unavailable');
      const existing = records.find((c) => c.tenant_id === tid && c.hostname === host);
      if (existing?.status === 'active') throw fail(409, 'hostname_unavailable');
      if (existing) return { status: 200, body: present(existing) };
      if (records.filter((c) => c.tenant_id === tid).length >= body.hostname_limit) throw fail(409, 'hostname_limit_reached');
      const time = now();
      const record = { tenant_id: tid, hostname: host, status: 'pending', created_at: new Date(time).toISOString(),
        expires_at: new Date(time + DAY).toISOString(), txt_value: `fd-verify=${randomBytes(16).toString('hex')}`,
        verified_at: null, method: null, credential_id: null };
      save([...records, record]);
      return { status: 201, body: present(record) };
    },
    async verify(tid, host, signal) {
      const initial = find(claims(), tid, host);
      limit(`verify:${tid}`, 6, 60000);
      const activeResult = (c) => ({ hostname: host, status: 'active', verified: true, verified_at: c.verified_at, method: c.method });
      if (initial.status === 'active') return activeResult(initial);
      if (unavailable(claims(), tid, host)) throw fail(409, 'hostname_unavailable');
      const expected_name = `_fastdog-challenge.${host}`;
      const [routing, ownership] = await Promise.all([
        timed(() => checkDnsVerification(host, { resolver, attachTarget, altAttachTarget, edgePublicIp: opts.edgePublicIp ?? edgeIp() }))
          .then(({ verified, ...check }) => ({ ok: verified, ...check }), () => ({ ok: false, error: 'dns_timeout' })),
        timed(() => resolver.resolveTxt(expected_name)).then((records) => {
          const ok = records.some((parts) => parts.join('') === initial.txt_value);
          return ok ? { ok: true } : { ok: false, error: records.length ? 'txt_mismatch' : 'txt_not_found', expected_name };
        }, (error) => ({ ok: false, error: ['ENOTFOUND', 'ENODATA'].includes(error.code) ? 'txt_not_found' : 'dns_timeout', expected_name })),
      ]);
      // Re-read after DNS: another request may have activated, deleted or replaced this claim.
      const records = claims();
      const record = find(records, tid, host);
      if (record.txt_value !== initial.txt_value || signal?.aborted) throw fail(404, 'hostname_not_found');
      if (unavailable(records, tid, host)) throw fail(409, 'hostname_unavailable');
      if (record.status === 'active') return activeResult(record);
      if (!routing.ok || !ownership.ok) return { hostname: host, status: 'pending', verified: false, checks: { routing, ownership } };
      // Single writer: there are no awaits between the ownership check and these writes.
      registry?.closeHost(host);
      const credential = issueCredential({ tenant_id: tid, hostname: host, name: host }, directory, now);
      Object.assign(record, { status: 'active', verified_at: new Date(now()).toISOString(), method: routing.method, credential_id: credential.id });
      save(records);
      write('tunnel_hosts.json', [...new Set([...read('tunnel_hosts.json'), host])]);
      changed();
      return { ...activeResult(record), credential };
    },
    rotate(tid, host) {
      const records = claims();
      const record = find(records, tid, host);
      active(record);
      limit(`rotate:${host}`, 5, DAY);
      revoke(tid, host);
      registry?.closeHost(host);
      const credential = issueCredential({ tenant_id: tid, hostname: host, name: host }, directory, now);
      record.credential_id = credential.id;
      save(records);
      return { credential };
    },
    agent(tid, host) { active(find(claims(), tid, host)); return agent(host); },
    delete(tid, host) {
      const records = claims();
      const record = find(records, tid, host);
      save(records.filter((c) => c !== record));
      write('agent-credentials.json', read('agent-credentials.json').filter((c) => c.tenant_id !== tid || c.claim_hostname !== host));
      if (record.status === 'active') {
        write('tunnel_hosts.json', read('tunnel_hosts.json').filter((h) => h !== host));
        registry?.closeHost(host);
        changed();
      }
      return { hostname: host, detached: true };
    },
    ask(input) {
      limit('tls-ask', 6000, 60000);
      let host;
      try { host = normalizeHostname(input); } catch { return false; }
      return claims().some((c) => c.hostname === host && c.status === 'active') || legacy(host)?.status === 'active';
    },
  };
}
