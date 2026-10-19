import { jsonClient } from './http-client.js';
import { fail } from './errors.js';
import { normalizeHostname } from './hostname.js';
export function createEdgeClient({ baseUrl = 'http://127.0.0.1:8789', portalKey, timeout = 5000 }) {
  if (typeof portalKey !== 'string' || portalKey.length < 32) throw new Error('Portal key required');
  const call = jsonClient({ baseUrl, timeout, headers: { 'x-fastdog-portal-key': portalKey } });
  // Agent bootstrap routes map their edge errors onto portal-only codes, so existing routes keep their error mapping.
  const bootstrapCall = jsonClient({ baseUrl, timeout, headers: { 'x-fastdog-portal-key': portalKey }, errorMap: {
    bootstrap_unavailable: 'agent_bootstrap_unavailable', bootstrap_not_found: 'agent_bootstrap_not_found',
    candidate_not_found: 'candidate_not_found', candidate_mismatch: 'candidate_mismatch' } });
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
    // Agent bootstrap (PORTAL_AGENT_BOOTSTRAP_ENABLED=1 only). Issuance returns the one-time code exactly once.
    issueBootstrap: (tid, hostname, body) => bootstrapCall(`${route(tid, hostname)}/bootstraps`, 'POST', body),
    getBootstrap: (tid, hostname, id) => bootstrapCall(`${route(tid, hostname)}/bootstraps/${encodeURIComponent(id)}`),
    cancelBootstraps: (tid, hostname) => bootstrapCall(`${route(tid, hostname)}/bootstraps`, 'DELETE'),
    revokeAgent: (tid, hostname) => bootstrapCall(`${route(tid, hostname)}/bootstraps/agent/revoke`, 'POST'),
    confirmCandidate: (tid, hostname, id, keyFingerprint) => bootstrapCall(`${route(tid, hostname)}/bootstraps/candidates/${encodeURIComponent(id)}/confirm`, 'POST', { key_fingerprint: keyFingerprint }),
  };
}
