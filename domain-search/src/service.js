import { readFileSync, writeFileSync, renameSync } from 'node:fs';
const DEFAULT_TLDS = Object.freeze(['com', 'net', 'org', 'dev', 'app', 'io', 'co']);
const RATE_WINDOW = 10 * 60 * 1_000;

export function normalizeDomain(name, alternates = DEFAULT_TLDS) {
  if (typeof name !== 'string') return null;
  const normalized = name.toLowerCase().replace(/\.$/, '');
  if (normalized.length > 253) return null;
  const parts = normalized.split('.');
  const [label, tld = 'com'] = parts;
  if (parts.length > 2 || !alternates.includes(tld)
    || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
    || label.slice(2, 4) === '--') return null;
  return `${label}.${tld}`;
}

export function createService({
  registrar, now = Date.now, cacheTTL = 3 * 60 * 60 * 1_000,
  perIpLimit = 10, dailyCap = 300, alternates = DEFAULT_TLDS, statePath,
} = {}) {
  const cache = new Map();
  const pending = new Map();
  const clients = new Map();
  const tlds = [...new Set(alternates)];
  let day;
  let calls = 0;
  const today = () => new Date(now()).toISOString().slice(0, 10);
  // Optional persistence of the daily counter; any bad or stale file resets to zero.
  if (statePath) {
    try {
      const saved = JSON.parse(readFileSync(statePath, 'utf8'));
      if (saved.day === today() && Number.isInteger(saved.calls) && saved.calls >= 0) { day = saved.day; calls = saved.calls; }
    } catch { /* missing or unreadable: start from zero */ }
  }
  function save() {
    if (!statePath) return;
    try { writeFileSync(`${statePath}.tmp`, JSON.stringify({ day, calls })); renameSync(`${statePath}.tmp`, statePath); }
    catch { /* persistence is best effort */ }
  }

  function rateLimit(ip) {
    const time = Number(now());
    for (const [key, value] of clients) if (value.reset <= time) clients.delete(key);
    let client = clients.get(ip);
    // Bound memory without evicting active limits and allowing a bypass.
    if (!client && clients.size >= 10_000) return { allowed: false, retryAfter: 600 };
    if (!client) {
      client = { count: 0, reset: time + RATE_WINDOW };
      clients.set(ip, client);
    }
    if (client.count >= perIpLimit) {
      return { allowed: false, retryAfter: Math.max(1, Math.ceil((client.reset - time) / 1_000)) };
    }
    client.count++;
    return { allowed: true };
  }

  async function upstream(method, ...args) {
    const currentDay = today();
    if (day !== currentDay) { day = currentDay; calls = 0; }
    if (calls >= dailyCap) throw 'daily_cap';
    // Reserve synchronously before awaiting, including failed calls.
    calls++;
    save();
    try { return await registrar[method](...args); }
    catch { throw 'upstream_unavailable'; }
  }

  const empty = (domain) => ({ domain, status: 'unknown', premium: false,
    price_year: null, price_renewal: null, currency: 'USD' });
  function price(response) {
    const value = response?.attributes?.price;
    if (response?.is_success !== '1' || response.response_code !== '200'
      || typeof value !== 'string' || !/^\d{1,9}(?:\.\d{1,2})?$/.test(value)) {
      throw 'upstream_unavailable';
    }
    return Number(value).toFixed(2);
  }
  async function fetchDomain(domain) {
    let result = empty(domain);
    try {
      const lookup = await upstream('lookup', domain);
      const status = lookup?.attributes?.status;
      if (lookup?.is_success !== '1'
        || !((lookup.response_code === '210' && status === 'available')
          || (lookup.response_code === '211' && status === 'taken'))) throw 'upstream_unavailable';
      result.status = status;
      result.premium = lookup.attributes.reason === 'Premium Name';
      if (status === 'available') {
        for (const [type, field] of [['new', 'price_year'], ['renewal', 'price_renewal']]) {
          const response = await upstream('getPrice', domain, type);
          result.premium ||= response?.attributes?.is_registry_premium === '1';
          result[field] = price(response);
        }
      }
      // Failed or incomplete entries are not cached, so later searches can recover.
      cache.set(domain, { result: { ...result }, expires: Number(now()) + cacheTTL });
      return { result };
    } catch (error) {
      const degraded = error === 'daily_cap' ? 'daily_cap' : 'upstream_unavailable';
      if (degraded !== 'daily_cap') result = { ...empty(domain), premium: result.premium };
      return { result, degraded };
    }
  }

  async function search(name) {
    const query = normalizeDomain(name, tlds);
    if (!query) return { error: 'invalid_domain' };
    const label = query.split('.')[0];
    const domains = [query, ...tlds.map((tld) => `${label}.${tld}`).filter((domain) => domain !== query).slice(0, 4)];
    const response = { query, results: [], cached: true };
    for (const [domain, entry] of cache) if (entry.expires <= Number(now())) cache.delete(domain);
    for (const domain of domains) {
      const cached = cache.get(domain);
      if (cached && cached.expires > Number(now())) {
        response.results.push({ ...cached.result });
        continue;
      }
      response.cached = false;
      // Share in-flight work so concurrent identical searches do not drain the budget.
      if (!pending.has(domain)) pending.set(domain, fetchDomain(domain).finally(() => pending.delete(domain)));
      const entry = await pending.get(domain);
      response.results.push({ ...entry.result });
      if (entry.degraded && response.degraded !== 'daily_cap') response.degraded = entry.degraded;
    }
    return response;
  }
  return { search, rateLimit };
}
