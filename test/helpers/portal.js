import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { fixedClock } from './clock.js';
import { tempDir } from './temp-dir.js';
import { listen, jsonRequest } from './http.js';
import { fakeSecret } from './internal.js';
import { tenants } from './fixtures.js';

export const portalFile = new URL('../../portal/src/app.js', import.meta.url);
export const invitesFile = new URL('../../portal/src/invites.js', import.meta.url);
export const portalOrigin = 'https://portal.example.test';

export function recordingEdge() {
  const calls = [];
  const records = new Map();
  const edge = { calls, records };
  for (const method of ['createHostname', 'listHostnames', 'getHostname', 'verifyHostname', 'rotateCredential', 'getAgent', 'deleteHostname']) {
    edge[method] = async (tenantId, hostname, hostnameLimit) => {
      calls.push({ method, tenantId, hostname, hostnameLimit });
      const hosts = records.get(tenantId) || [];
      if (method === 'listHostnames') return { hostnames: hosts };
      if (method === 'createHostname') {
        const record = { hostname, status: 'pending' };
        records.set(tenantId, [...hosts, record]);
        return record;
      }
      if (!hosts.some((record) => record.hostname === hostname)) {
        throw Object.assign(new Error('hostname_not_found'), { code: 'hostname_not_found', status: 404 });
      }
      if (method === 'getAgent') return { connected: false, last_seen: null, registered_at: null };
      if (method === 'deleteHostname') return { hostname, detached: true };
      if (method === 'rotateCredential') return { credential: { id: fakeSecret(), token: fakeSecret() } };
      if (method === 'verifyHostname') return { hostname, status: 'pending', verified: false };
      return hosts.find((record) => record.hostname === hostname);
    };
  }
  return edge;
}

export function browser(server) {
  const cookies = new Map();
  let csrf;
  const client = {
    csrf: () => csrf,
    async request(path, opts = {}) {
      const response = await jsonRequest(server, path, {
        ...opts,
        headers: { origin: portalOrigin, cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join('; '),
          ...(csrf ? { 'x-fd-csrf': csrf } : {}), ...opts.headers },
      });
      for (const cookie of response.headers['set-cookie'] || []) {
        const pair = cookie.split(';', 1)[0];
        const index = pair.indexOf('=');
        cookies.set(pair.slice(0, index), pair.slice(index + 1));
      }
      if (response.body?.csrf) csrf = response.body.csrf;
      return response;
    },
  };
  return client;
}

export async function portalHarness(t) {
  const { createApp } = await import(portalFile.href);
  const clock = fixedClock();
  const dataDir = tempDir(t);
  const edge = recordingEdge();
  const messages = [];
  const server = await listen(t, createApp({ dataDir, edge, now: clock.now,
    mailer: { send: async (message) => { messages.push(message); } },
    domainSearch: { search: async () => ({ results: [] }) },
    config: { origin: portalOrigin },
  }));
  return { server, edge, clock, dataDir, messages };
}

export async function twoAccounts(t) {
  if (!existsSync(invitesFile)) { t.skip('lane B invite store absent: signup cannot be seeded through its public API'); return; }
  const invites = await import(invitesFile.href);
  const mint = invites.generateInvite || invites.mintInvite || invites.createInvite;
  if (typeof mint !== 'function') {
    t.skip('lane B invite mint export absent; adapt helper after reading the merged invite store');
    return;
  }
  const h = await portalHarness(t);
  h.accounts = [];
  for (let i = 0; i < 2; i++) {
    const email = `${i === 0 ? 'a' : 'b'}@example.test`;
    const password = fakeSecret();
    // This adapter is the only invite-store integration point; no hand-written storage records.
    const invite = await mint({ dataDir: h.dataDir, email, tenant_id: tenants[i], hostname_limit: 3,
      max_uses: 1, now: h.clock.now, expires_in_hours: 1 });
    const inviteCode = typeof invite === 'string' ? invite : invite.code;
    assert.equal(typeof inviteCode, 'string');
    const client = browser(h.server);
    await client.request('/api/me');
    const signup = await client.request('/api/signup', { method: 'POST', body: { email, password, invite_code: inviteCode } });
    assert.ok(signup.status >= 200 && signup.status < 300, 'signup with a freshly minted invite must succeed');
    const mail = h.messages.find((message) => message.to === email);
    assert.ok(mail, 'signup must send a verification link to the injected mailer');
    const link = new URL(mail.link, portalOrigin);
    const token = link.searchParams.get('token') || new URLSearchParams(link.hash.slice(1)).get('token');
    assert.ok(token, 'verification link must carry the one-time token');
    const verify = await client.request('/api/verify-email', { method: 'POST', body: { token } });
    assert.ok(verify.status >= 200 && verify.status < 300);
    const login = await client.request('/api/login', { method: 'POST', body: { email, password } });
    assert.equal(login.status, 200);
    const me = await client.request('/api/me');
    assert.equal(me.status, 200);
    assert.match(me.body.tenant.id, /^t_[a-z2-7]{20}$/);
    assert.equal(typeof me.body.csrf, 'string');
    h.accounts.push({ email, password, client, login, me: me.body, tenantId: me.body.tenant.id });
  }
  assert.notEqual(h.accounts[0].tenantId, h.accounts[1].tenantId);
  return h;
}
