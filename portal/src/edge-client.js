import { jsonClient } from './http-client.js';
import { fail } from './errors.js';
import { normalizeHostname } from './hostname.js';
export function createEdgeClient({ baseUrl = 'http://127.0.0.1:8789', portalKey, timeout = 5000 }) {
  if (typeof portalKey !== 'string' || portalKey.length < 32) throw new Error('Portal key required');
  const call = jsonClient({ baseUrl, timeout, headers: { 'x-fastdog-portal-key': portalKey } });
  const route = (tid, host) => {
    if (!/^t_[a-z2-7]{20}$/.test(tid)) throw fail('invalid_tenant');
    return `/internal/v1/tenants/${tid}/hostnames${host === undefined ? '' : `/${encodeURIComponent(normalizeHostname(host))}`}`;
  };
  return {
    createHostname: (tid, hostname, hostnameLimit) => call(route(tid), 'POST', { hostname: normalizeHostname(hostname), hostname_limit: hostnameLimit }),
    listHostnames: (tid) => call(route(tid)),
    getHostname: (tid, hostname) => call(route(tid, hostname)),
    verifyHostname: (tid, hostname) => call(`${route(tid, hostname)}/verify`, 'POST'),
    rotateCredential: (tid, hostname) => call(`${route(tid, hostname)}/credentials/rotate`, 'POST'),
    getAgent: (tid, hostname) => call(`${route(tid, hostname)}/agent`),
    deleteHostname: (tid, hostname) => call(route(tid, hostname), 'DELETE'),
  };
}
