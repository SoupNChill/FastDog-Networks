// Shadow scoring for customer hosts, from the scrubbed per-host Caddy logs
// (deploy/caddy/access-logs.snippet: /var/log/caddy/<hostname>.log, client IP masked to /24 or /48,
// no headers, no query strings, no host field). Shadow only: nothing here is ever enforced, and the
// output is per-host counts only (no paths, IPs or user agents), so each tenant's status page can
// show its own numbers without seeing anyone else's traffic.
import { readFile, writeFile, rename, readdir, stat, open } from 'node:fs/promises';
import { join } from 'node:path';
import { localHeuristic } from '../engine/heuristic.js';
import { lookupAsn } from '../asn/lookup.js';

const HOUR = 3600000;
const KEEP_HOURS = 25;
const MAX_HOSTS = 2000;
const MAX_READ = 4 * 1024 * 1024;
const ROLLED_RE = /-\d{4}-\d{2}-\d{2}t\d{2}-\d{2}-\d{2}(?:\.\d+)?$/;
export const HOST_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

// Hosts the first-party scorer already handles from the unscrubbed logs; never double counted here.
export function excludedHosts(env = process.env) {
  return new Set(String(env.VERDICT_SHADOW_CUSTOMER_EXCLUDE || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean));
}

// Score one scrubbed log line. Header and user-agent signals are unknown (not "missing") because the
// log never had them, so only path, method and network (ASN of the masked prefix) signals can fire.
export function scoreScrubbedLine(line, { hosting } = {}) {
  let row;
  try { row = typeof line === 'string' ? JSON.parse(line) : line; } catch { return null; }
  if (!row || typeof row !== 'object') return null;
  const req = row.request || {};
  const prefix = typeof req.client_ip === 'string' ? req.client_ip : '';
  const asnInfo = prefix ? lookupAsn(prefix) : null;
  const decision = localHeuristic({ path: typeof req.uri === 'string' ? req.uri : '/', method: typeof req.method === 'string' ? req.method : 'GET',
    asn: asnInfo?.asn, hosting_asn: Boolean(hosting && asnInfo && hosting.has(asnInfo.asn)) });
  return decision.action;
}

export function createCountStore(file, { now = Date.now } = {}) {
  let data = { v: 1, hosts: {} };
  let dirty = false;
  const prune = () => {
    const oldest = Math.floor(now() / HOUR) - KEEP_HOURS;
    for (const [host, buckets] of Object.entries(data.hosts)) {
      for (const hour of Object.keys(buckets)) if (Number(hour) < oldest) delete buckets[hour];
      if (!Object.keys(buckets).length) delete data.hosts[host];
    }
  };
  return {
    async load() {
      try {
        const parsed = JSON.parse(await readFile(file, 'utf8'));
        if (parsed && parsed.v === 1 && parsed.hosts && typeof parsed.hosts === 'object') data = parsed;
      } catch { /* Start empty: fail-open, counts are advisory. */ }
      prune();
    },
    add(host, action, at = now()) {
      if (!HOST_RE.test(host)) return;
      if (!data.hosts[host] && Object.keys(data.hosts).length >= MAX_HOSTS) return;
      const hour = String(Math.floor(at / HOUR));
      const buckets = (data.hosts[host] ||= {});
      const b = (buckets[hour] ||= { scored: 0, block: 0, challenge: 0 });
      b.scored++;
      if (action === 'block') b.block++;
      else if (action === 'challenge') b.challenge++;
      dirty = true;
    },
    async flush() {
      if (!dirty) return false;
      prune();
      const tmp = `${file}.tmp`;
      await writeFile(tmp, JSON.stringify({ ...data, updated_at: new Date(now()).toISOString() }), { mode: 0o640 });
      await rename(tmp, file);
      dirty = false;
      return true;
    },
    snapshot: () => structuredClone(data),
  };
}

// Tails every per-host log in logDir. A newly seen file starts at its end (scrubbed lines carry no
// timestamp, so old lines can't be placed in time); a shrunk file (rotation) starts over.
export function createCustomerTail({ logDir, store, hosting, exclude = new Set(), now = Date.now, score = scoreScrubbedLine }) {
  const offsets = new Map();
  async function hosts() {
    let names;
    try { names = await readdir(logDir); } catch { return []; }
    return names.filter((n) => n.endsWith('.log')).map((n) => n.slice(0, -4).toLowerCase())
      // Caddy's rolled copies (<host>-YYYY-MM-DDTHH-MM-SS.mmm.log) are skipped; only the live file is tailed.
      .filter((h) => HOST_RE.test(h) && !ROLLED_RE.test(h) && !exclude.has(h)).slice(0, MAX_HOSTS);
  }
  async function consume(host) {
    const file = join(logDir, `${host}.log`);
    let size;
    try { size = (await stat(file)).size; } catch { return 0; }
    if (!offsets.has(host)) { offsets.set(host, size); return 0; }
    let start = offsets.get(host);
    if (size < start) start = 0;
    if (size === start) return 0;
    const end = Math.min(size, start + MAX_READ);
    const handle = await open(file, 'r');
    let text;
    try {
      const buffer = Buffer.alloc(end - start);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, start);
      text = buffer.subarray(0, bytesRead).toString('utf8');
    } finally { await handle.close(); }
    const last = text.lastIndexOf('\n');
    if (last < 0) { if (end === size && end - start >= MAX_READ) offsets.set(host, end); return 0; }
    offsets.set(host, start + Buffer.byteLength(text.slice(0, last + 1)));
    let n = 0;
    for (const line of text.slice(0, last).split('\n')) {
      if (!line.trim()) continue;
      const action = score(line, { hosting });
      if (action) { store.add(host, action, now()); n++; }
    }
    return n;
  }
  return {
    async poll() {
      let n = 0;
      for (const host of await hosts()) {
        try { n += await consume(host); } catch { /* One unreadable file never stops the rest. */ }
        await new Promise((r) => setImmediate(r));
      }
      await store.flush();
      return n;
    },
    offsets,
  };
}
