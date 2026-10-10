import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { tempDir } from './temp-dir.js';
import { fixedClock } from './clock.js';
import { fakeResolver } from './resolver.js';
import { listen, jsonRequest } from './http.js';
import { attachTarget, altAttachTarget, edgePublicIp, reservedSuffixes } from './fixtures.js';

export const internalFile = new URL('../../src/internal/server.js', import.meta.url);
export const fakeSecret = () => `fake-test-only-${randomBytes(32).toString('hex')}`;
export const hostPath = (tid, host = '', suffix = '') =>
  `/internal/v1/tenants/${tid}/hostnames${host ? `/${encodeURIComponent(host)}` : ''}${suffix}`;

export async function internalHarness(t, overrides = {}) {
  const { createInternalServer } = await import(internalFile.href);
  const clock = fixedClock();
  const resolver = fakeResolver();
  const closed = [];
  const agents = new Map();
  const logs = [];
  const log = (...args) => logs.push(args);
  const options = {
    dataDir: tempDir(t), portalKey: fakeSecret(), agentToken: fakeSecret(),
    attachTarget, altAttachTarget, edgePublicIp, reservedSuffixes, resolver,
    now: clock.now, logger: Object.assign(log, { info: log, warn: log, error: log }),
    registry: { getAgentByHost: (host) => agents.get(host) || null, closeHost: (host) => closed.push(host) },
    ...overrides,
  };
  const server = await listen(t, createInternalServer(options));
  const request = (path, opts = {}) => jsonRequest(server, path, {
    ...opts, headers: { 'x-fastdog-portal-key': options.portalKey, ...opts.headers },
  });
  const create = (tid, hostname, hostname_limit = 100) => request(hostPath(tid), {
    method: 'POST', body: { hostname, hostname_limit },
  });
  const prove = (claim) => {
    resolver.set('CNAME', claim.hostname, [attachTarget]);
    resolver.set('TXT', `_fastdog-challenge.${claim.hostname}`, [[claim.dns.txt.value]]);
  };
  const activate = async (tid, hostname) => {
    const response = await create(tid, hostname);
    assert.equal(response.status, 201);
    prove(response.body);
    const active = await request(hostPath(tid, hostname, '/verify'), { method: 'POST' });
    assert.equal(active.status, 200);
    assert.equal(active.body.verified, true);
    assert.equal(active.body.status, 'active');
    assert.match(active.body.credential.token, /^[a-f0-9]{64}$/);
    closed.length = 0; // activation drops any stale tunnel for the host by design; tests assert later closes
    return active.body;
  };
  return { ...options, server, request, create, prove, activate, clock, resolver, closed, agents, logs };
}
