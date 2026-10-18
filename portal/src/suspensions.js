// Operator kill switch state. suspensions.json is written only by portal/bin/tenant.js; the server
// reads it on every identity, key and token check and never writes it, so the CLI can run while the
// portal is up without racing the server's writes to accounts.json.
// Entry: { at, reason, revoked_before, edge_ok, resumed_at? }; edge_ok records whether the edge suspend succeeded. Resume keeps the entry (resumed_at set), so every
// session, API key and connect token issued at or before revoked_before stays invalid, used or not.
const empty = () => ({ tenants: {} });
const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const time = (value) => (typeof value === 'number' ? value : Date.parse(value));

export function createSuspensions(store) {
  const read = () => {
    const value = store.read('suspensions', empty());
    // A file with the wrong shape fails closed (like invalid JSON) instead of silently dropping every suspension.
    if (!plain(value) || !plain(value.tenants) || !Object.values(value.tenants).every(plain)) throw new Error('Invalid suspensions.json');
    return value;
  };
  const entry = (tid) => (typeof tid === 'string' && Object.hasOwn(read().tenants, tid) ? read().tenants[tid] : null);
  const epoch = (tid) => { const e = entry(tid); return e ? (Number.isFinite(e.revoked_before) ? e.revoked_before : time(e.at)) : null; };
  return {
    has: (tid) => { const e = entry(tid); return Boolean(e && !e.resumed_at); },
    known: (tid) => entry(tid) !== null,
    get: entry,
    // True when a credential issued at createdAt (ms or ISO) predates the tenant's last suspension. Fails closed.
    stale(tid, createdAt) { const e = epoch(tid); if (e === null) return false; const c = time(createdAt); return !Number.isFinite(c) || !Number.isFinite(e) || c <= e; },
    // CLI only.
    set(tid, value) { const all = read(); all.tenants[tid] = value; store.write('suspensions', all); },
    update(tid, patch) { const all = read(); if (Object.hasOwn(all.tenants, tid)) { all.tenants[tid] = { ...all.tenants[tid], ...patch }; store.write('suspensions', all); } },
    clear(tid, at) {
      const all = read();
      const e = all.tenants[tid];
      if (!Object.hasOwn(all.tenants, tid) || e.resumed_at) return false;
      all.tenants[tid] = { ...e, revoked_before: Number.isFinite(e.revoked_before) ? e.revoked_before : time(e.at), resumed_at: at };
      store.write('suspensions', all);
      return true;
    },
  };
}
// The tenant as every check should see it: a listed tenant is suspended whatever accounts.json says.
export const effectiveTenant = (tenant, suspensions) => (tenant && suspensions.has(tenant.id) ? { ...tenant, status: 'suspended' } : tenant);
