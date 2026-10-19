import { jsonClient } from './http-client.js';
import { fail } from './errors.js';
import { normalizeHostname } from './hostname.js';
export function createEdgeClient({ baseUrl = 'http://127.0.0.1:8789', portalKey, timeout = 5000 }) {
  if (typeof portalKey !== 'string' || portalKey.length < 32) throw new Error('Portal key required');
  const call = jsonClient({ baseUrl, timeout, headers: { 'x-fastdog-portal-key': portalKey } });
  const tenant = (tid) => {
    if (!/^t_[a-z2-7]{20}$/.test(tid)) throw fail('invalid_tenant');
    return `/internal/v1/tenants/${tid}`;
  };
  const route = (tid, host) => `${tenant(tid)}/hostnames${host === undefined ? '' : `/${encodeURIComponent(normalizeHostname(host))}`}`;
  return {
    createHostname: (tid, hostname, hostnameLimit) => call(route(tid), 'POST', { hostname: normalizeHostname(hostname), hostname_limit: hostnameLimit }),
    listHostnames: (tid) => call(route(tid)),
    getHostname: (tid, hostname) => call(route(tid, hostname)),
    verifyHostname: (tid, hostname) => call(`${route(tid, hostname)}/verify`, 'POST'),
    rotateCredential: (tid, hostname) => call(`${route(tid, hostname)}/credentials/rotate`, 'POST'),
    getAgent: (tid, hostname) => call(`${route(tid, hostname)}/agent`),
    getStatus: (tid, hostname) => call(`${route(tid, hostname)}/status`),
    testSite: (tid, hostname) => call(`${route(tid, hostname)}/test`, 'POST'),
    deleteHostname: (tid, hostname) => call(route(tid, hostname), 'DELETE'),
    // Kill switch (portal/bin/tenant.js): suspends every claim of the tenant and drops its tunnels and credentials.
    suspendTenant: (tid) => call(`${tenant(tid)}/suspend`, 'POST'),
    // Admin release: drops the tenant's administrative reservations so the hostnames can be claimed again.
    releaseTenant: (tid) => call(`${tenant(tid)}/release`, 'POST'),
    // Trial pause (portal/src/trials.js): the edge serves a paused page; nothing is removed. Both are idempotent.
    pauseTenant: (tid) => call(`${tenant(tid)}/pause`, 'POST'),
    unpauseTenant: (tid) => call(`${tenant(tid)}/unpause`, 'POST'),
  };
}
