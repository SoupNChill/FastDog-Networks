import { fail } from './errors.js';
export function createRateLimits(now, store) {
  const memory = new Map();
  function take(key, limit, window, persistent = false) {
    const time = now();
    let entries;
    if (persistent) entries = new Map(Object.entries(store.read('rate_limits', {})));
    else entries = memory;
    for (const [name, entry] of entries) if (entry.reset <= time) entries.delete(name);
    const prefix = key.split(':', 1)[0];
    let prefixSize = 0;
    if (!entries.has(key)) {
      for (const name of entries.keys()) if (name === prefix || name.startsWith(`${prefix}:`)) prefixSize++;
    }
    const entry = entries.get(key) || { count: 0, reset: time + window };
    if (entry.count >= limit) throw fail('rate_limited', Math.max(1, Math.ceil((entry.reset - time) / 1000)));
    if (!entries.has(key) && prefixSize >= 20000) {
      throw Object.assign(fail('rate_limited', Math.max(1, Math.ceil((entry.reset - time) / 1000))), { capacity: true });
    }
    entry.count++;
    entries.set(key, entry);
    if (persistent) store.write('rate_limits', Object.fromEntries(entries));
  }
  // Reserve a slot before asynchronous password derivation; refund successful logins.
  function refund(key, persistent = false) {
    const saved = persistent ? store.read('rate_limits', {}) : null;
    const entry = persistent ? saved[key] : memory.get(key);
    if (entry) entry.count = Math.max(0, entry.count - 1);
    if (persistent) store.write('rate_limits', saved);
  }
  return { take, refund };
}
