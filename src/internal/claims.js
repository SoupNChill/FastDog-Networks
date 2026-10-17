import { randomBytes } from 'node:crypto';
import dns from 'node:dns/promises';
import { readJson, writeJson, dataDir as defaultDataDir } from '../onboard/json.js';
import { issueCredential } from '../onboard/credentials.js';
import { normalizeHostname, isReserved } from '../onboard/hostname.js';
import { checkDnsVerification, attachTarget as defaultTarget, altAttachTarget as defaultAltTarget } from '../onboard/attach.js';
import { edgeIp } from '../onboard/store.js';
import { reservedSuffixes as defaultSuffixes } from '../lib/config.js';
import { mayClaimTestLabel, isTestLabelHost, isGuardrailHost } from './test-labels.js';

export const fail = (status, code, extra = {}) => Object.assign(new Error(code), { status, code, ...extra });
const DAY = 86400000;
const MIN_OUTAGE_SAMPLE = 10;

// Host and port only (never userinfo or path); limited to address characters because the agent chooses it.
const originAddress = (upstream) => { try { const host = upstream ? new URL(upstream).host : ''; return /^[a-z0-9.:[\]-]{1,100}$/i.test(host) ? host : null; } catch { return null; } };

async function timed(fn, ms = 3500) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(fn), new Promise((_, reject) => {
      timer = setTimeout(() => reject(fail(200, 'dns_timeout')), ms);
    })]);
  } finally { clearTimeout(timer); }
}

// The DNS proof a claim needs at verify time: routing to the edge plus the challenge TXT record.
// Shared with the TLS ask live check. A DNS error or timeout yields error 'dns_timeout' (inconclusive).
export async function checkClaimProof(host, txtValue, { resolver, attachTarget, altAttachTarget, edgePublicIp, timeout }) {
  const expected_name = `_fastdog-challenge.${host}`;
  const [routing, ownership] = await Promise.all([
    timed(() => checkDnsVerification(host, { resolver, attachTarget, altAttachTarget, edgePublicIp }), timeout)
      .then(({ verified, ...check }) => ({ ok: verified, ...check }), () => ({ ok: false, error: 'dns_timeout' })),
    timed(() => resolver.resolveTxt(expected_name), timeout).then((records) => {
      const ok = records.some((parts) => parts.join('') === txtValue);
      return ok ? { ok: true } : { ok: false, error: records.length ? 'txt_mismatch' : 'txt_not_found', expected_name };
    }, (error) => ({ ok: false, error: ['ENOTFOUND', 'ENODATA'].includes(error.code) ? 'txt_not_found' : 'dns_timeout', expected_name })),
  ]);
  return { routing, ownership };
}

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
      registered_at: value?.registered_at ?? value?.registeredAt ?? null,
      origin_reachable: typeof value?.originReachable === 'boolean' ? value.originReachable : null,
      origin_checked_at: value?.originCheckedAt ?? null,
      origin_address: originAddress(value?.localUpstream),
      agent_version: typeof value?.agentVersion === 'string' ? value.agentVersion : null };
  }
  function present(c) {
    const record = { hostname: c.hostname, status: c.status, created_at: c.created_at };
    if (['active', 'suspended'].includes(c.status)) return { ...record, verified_at: c.verified_at, agent: c.status === 'active' ? agent(c.hostname) : null };
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
  let rechecking = false;
  async function recheckActiveClaims({ now: time = now(), resolver: lookup = resolver, failuresBeforeDemote = 3,
    inconclusiveBeforeFailure = opts.inconclusiveBeforeFailure ?? 8,
    minOutageSample = opts.minOutageSample ?? MIN_OUTAGE_SAMPLE } = {}) {
    if (!Number.isInteger(failuresBeforeDemote) || failuresBeforeDemote < 1) throw new RangeError('invalid failure threshold');
    if (!Number.isInteger(inconclusiveBeforeFailure) || inconclusiveBeforeFailure < 1) throw new RangeError('invalid inconclusive threshold');
    if (!Number.isInteger(minOutageSample) || minOutageSample < 1) throw new RangeError('invalid outage sample');
    if (rechecking) return;
    rechecking = true;
    try {
      const stamp = new Date(typeof time === 'function' ? time() : time).toISOString();
      const results = [];
      for (const initial of claims().filter((c) => c.status === 'active')) {
        // Use the original proof's record type. Chained CNAMEs use a recursive A
        // answer to check the edge address without walking the chain again.
        const useA = ['a_record', 'cname_chain'].includes(initial.method);
        let used = false;
        const once = (fn) => {
          if (used) return Promise.resolve([]);
          used = true;
          return fn();
        };
        const boundedResolver = {
          resolveCname: (host) => useA ? Promise.resolve([]) : once(() => lookup.resolveCname(host)),
          resolve4: (host) => useA ? once(() => lookup.resolve4(host)) : Promise.resolve([]),
        };
        const ok = await timed(() => checkDnsVerification(initial.hostname, {
          resolver: boundedResolver, attachTarget, altAttachTarget, edgePublicIp: opts.edgePublicIp ?? edgeIp(),
        })).then((result) => result.verified, () => null);
        results.push({ initial, ok });
      }
      // Require enough checked claims and cap each tenant at one majority vote.
      const tenants = new Map();
      for (const { initial, ok } of results) {
        const vote = tenants.get(initial.tenant_id) ?? { checked: 0, inconclusive: 0 };
        vote.checked++;
        if (ok === null) vote.inconclusive++;
        tenants.set(initial.tenant_id, vote);
      }
      const inconclusiveTenants = [...tenants.values()].filter((vote) => vote.inconclusive > vote.checked / 2).length;
      const outage = results.length >= minOutageSample && inconclusiveTenants > tenants.size / 2;
      for (const { initial, ok } of results) {
        if (ok === null && outage) continue;
        // DNS yields: never resurrect a deleted/replaced claim or overwrite another owner.
        const records = claims();
        const record = records.find((c) => c.tenant_id === initial.tenant_id && c.hostname === initial.hostname);
        if (!record || record.txt_value !== initial.txt_value || record.credential_id !== initial.credential_id ||
            record.status !== initial.status) continue;
        record.last_rechecked_at = stamp;
        record.recheck_inconclusive = ok === null ? (record.recheck_inconclusive ?? 0) + 1 : 0;
        if (ok === null && record.recheck_inconclusive < inconclusiveBeforeFailure) {
          save(records);
          continue;
        }
        record.recheck_failures = ok ? 0 : (record.recheck_failures ?? 0) + 1;
        const previous = record.status;
        if (!ok && record.recheck_failures >= failuresBeforeDemote) {
          record.status = 'suspended';
          record.expires_at = new Date(Date.parse(stamp) + DAY).toISOString();
          revoke(record.tenant_id, record.hostname);
        }
        save(records);
        if (previous !== record.status) {
          const hosts = read('tunnel_hosts.json');
          write('tunnel_hosts.json', hosts.filter((h) => h !== record.hostname));
          registry?.closeHost(record.hostname);
          changed();
        }
      }
    } finally { rechecking = false; }
  }
  return {
    recheckActiveClaims,
    list(tid) { return { hostnames: claims().filter((c) => c.tenant_id === tid).sort((a, b) => a.created_at.localeCompare(b.created_at)).map(present) }; },
    get(tid, host) { return present(find(claims(), tid, host)); },
    create(tid, body) {
      const host = normalizeHostname(body.hostname);
      if (isGuardrailHost(host)) throw fail(400, 'reserved_hostname');
      if (!mayClaimTestLabel(tid, host, attachTarget, altAttachTarget, directory)
        && (isReserved(host, reserved) || [attachTarget, altAttachTarget].filter(Boolean).some((target) => host === target.toLowerCase().replace(/\.$/, '')))) throw fail(400, 'reserved_hostname');
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
      // Unmarking a test tenant refuses further verification of its test labels; active claims are untouched.
      if (isTestLabelHost(host, attachTarget, altAttachTarget) && !mayClaimTestLabel(tid, host, attachTarget, altAttachTarget, directory)) throw fail(400, 'reserved_hostname');
      const { routing, ownership } = await checkClaimProof(host, initial.txt_value,
        { resolver, attachTarget, altAttachTarget, edgePublicIp: opts.edgePublicIp ?? edgeIp() });
      // Re-read after DNS: another request may have activated, deleted or replaced this claim.
      const records = claims();
      const record = find(records, tid, host);
      if (record.txt_value !== initial.txt_value || signal?.aborted) throw fail(404, 'hostname_not_found');
      if (unavailable(records, tid, host)) throw fail(409, 'hostname_unavailable');
      if (record.status === 'active') return activeResult(record);
      if (!routing.ok || !ownership.ok) return { hostname: host, status: record.status, verified: false, checks: { routing, ownership } };
      // Single writer: there are no awaits between the ownership check and these writes.
      registry?.closeHost(host);
      if (record.status === 'suspended') revoke(tid, host);
      const credential = issueCredential({ tenant_id: tid, hostname: host, name: host }, directory, now);
      Object.assign(record, { status: 'active', verified_at: new Date(now()).toISOString(), method: routing.method, credential_id: credential.id, recheck_failures: 0, recheck_inconclusive: 0 });
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
    // When this tenant's current claim became active (verified_at only; null makes the probes fail closed).
    claimSince(tid, host) { const c = find(claims(), tid, host); active(c); return c.verified_at || null; },
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
