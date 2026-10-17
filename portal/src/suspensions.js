// Operator kill switch state. suspensions.json is written only by portal/bin/tenant.js; the server
// reads it on every identity, key and token check and never writes it, so the CLI can run while the
// portal is up without racing the server's writes to accounts.json.
const empty = () => ({ tenants: {} });

export function createSuspensions(store) {
  const read = () => {
    const value = store.read('suspensions', empty());
    return value && typeof value.tenants === 'object' && value.tenants ? value : empty();
  };
  return {
    has: (tid) => typeof tid === 'string' && Object.hasOwn(read().tenants, tid),
    get: (tid) => (typeof tid === 'string' && Object.hasOwn(read().tenants, tid) ? read().tenants[tid] : null),
    // CLI only.
    set(tid, entry) { const all = read(); all.tenants[tid] = entry; store.write('suspensions', all); },
    clear(tid) {
      const all = read();
      if (!Object.hasOwn(all.tenants, tid)) return false;
      delete all.tenants[tid];
      store.write('suspensions', all);
      return true;
    },
  };
}
// The tenant as every check should see it: a listed tenant is suspended whatever accounts.json says.
export const effectiveTenant = (tenant, suspensions) => (tenant && suspensions.has(tenant.id) ? { ...tenant, status: 'suspended' } : tenant);
