import http from 'node:http';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createApp } from '../src/app.js';
import { createStore, emptyAccounts } from '../src/store.js';
import { hashPassword } from '../src/passwords.js';
import { fail } from '../src/errors.js';
export const origin = 'https://portal.example.test';
export const tids = ['t_aaaaaaaaaaaaaaaaaaaa', 't_bbbbbbbbbbbbbbbbbbbb', 't_cccccccccccccccccccc'];
export const fakeSecret = () => `fake-${randomBytes(24).toString('hex')}`;
export function temporary(t) {
  const dir = mkdtempSync(join(fileURLToPath(new URL('.', import.meta.url)), '.state-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
export async function listen(t, server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); }));
  return server.address().port;
}
export function request(port, path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers, agent: false }, (res) => {
      const parts = [];
      res.on('data', (chunk) => parts.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(parts).toString('utf8');
        let data;
        try { data = JSON.parse(text); } catch { data = text; }
        resolve({ status: res.statusCode, headers: res.headers, data, text });
      });
    });
    req.on('error', reject);
    req.end(body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body));
  });
}
export function browser(port) {
  let cookie;
  let csrf;
  const call = async (path, method = 'GET', body, overrides = {}) => {
    const result = await request(port, path, { method, body,
      headers: { ...(cookie ? { cookie } : {}), ...(method === 'GET' ? {} : { origin, 'x-fd-csrf': csrf || '', 'content-type': 'application/json' }), ...overrides } });
    if (result.headers['set-cookie']) cookie = result.headers['set-cookie'][0].split(';')[0];
    if (path === '/api/me') csrf = result.data.csrf;
    return result;
  };
  return { call, get cookie() { return cookie; }, get csrf() { return csrf; } };
}
export function fakeEdge() {
  const records = new Map();
  const calls = [];
  const key = (tid, host) => `${tid}:${host}`;
  const find = (tid, host) => {
    const record = records.get(key(tid, host));
    if (!record) throw fail('hostname_not_found');
    return record;
  };
  const credential = (hostname) => {
    const token = fakeSecret();
    return { id: fakeSecret(), token, agent_env: { AGENT_TOKEN: token, AGENT_HOSTNAME: hostname, AGENT_NAME: hostname } };
  };
  const edge = {
    async createHostname(tid, hostname, limit) {
      calls.push(['create', tid, hostname, limit]);
      const record = { hostname, status: 'pending', created_at: new Date(0).toISOString(), dns: {
        cname: { name: hostname, type: 'CNAME', value: 'attach.example-edge.test', ttl: 300 },
        txt: { name: `_fastdog-challenge.${hostname}`, type: 'TXT', value: fakeSecret(), ttl: 300 }, apex_note: null,
      } };
      records.set(key(tid, hostname), record);
      return record;
    },
    async listHostnames(tid) { calls.push(['list', tid]); return { hostnames: [...records].filter(([id]) => id.startsWith(`${tid}:`)).map(([, value]) => value) }; },
    async getHostname(tid, host) { calls.push(['get', tid, host]); return find(tid, host); },
    async verifyHostname(tid, host) {
      calls.push(['verify', tid, host]);
      const record = find(tid, host);
      const first = record.status !== 'active';
      record.status = 'active';
      return { hostname: host, status: 'active', verified: true, ...(first ? { credential: credential(host) } : {}) };
    },
    async rotateCredential(tid, host) {
      calls.push(['rotate', tid, host]);
      if (find(tid, host).status !== 'active') throw fail('not_active');
      return { credential: credential(host) };
    },
    async getAgent(tid, host) { calls.push(['agent', tid, host]); find(tid, host); return { connected: false, last_seen: null, registered_at: null }; },
    async getStatus(tid, host) {
      calls.push(['status', tid, host]);
      if (find(tid, host).status !== 'active') throw fail('not_active');
      return { hostname: host, live: true, reasons: [], checked_at: new Date(0).toISOString(), log_path: '/internal/only',
        agent: { connected: true, origin_reachable: true, agent_version: '0.1.2', origin_address: '127.0.0.1:3000' },
        cert: { valid: true, expires_at: '2099-01-01T00:00:00.000Z', issuer: 'Test CA', serial: 'internal' },
        traffic: { available: true, total: 1, hourly: new Array(24).fill(0), p50_ms: 2, errors_5xx: 0, file: '/internal' },
        verdict: { available: true, shadow: true, scored: 1, would_block: 0, would_challenge: 1, file: '/internal' } };
    },
    async testSite(tid, host) {
      calls.push(['test', tid, host]);
      if (find(tid, host).status !== 'active') throw fail('not_active');
      return { hostname: host, tested_at: new Date(0).toISOString(), ok: true, status: 200, ms: 9, error: null, cert: null, upstream: '10.0.0.1' };
    },
    async deleteHostname(tid, host) { calls.push(['delete', tid, host]); find(tid, host); records.delete(key(tid, host)); return { hostname: host, detached: true }; },
  };
  return { edge, records, calls };
}
// options.edge replaces the fake edge (for example a real edge client against a loopback internal server);
// options.mailer replaces the recording mailer; options.ownerNotify is passed to createApp.
export async function fixture(t, config = {}, options = {}) {
  const dataDir = temporary(t);
  const store = createStore(dataDir);
  let clock = Date.parse('2026-01-01T00:00:00Z');
  const now = () => clock;
  const messages = [];
  const searches = [];
  const fake = fakeEdge();
  const app = createApp({ dataDir, now, ownerNotify: options.ownerNotify, edge: options.edge ?? fake.edge, mailer: options.mailer || { async send(message) { messages.push(message); } },
    domainSearch: { async search(q, ip) { searches.push([q, ip]); return { results: [] }; } }, config: { origin, ...config } });
  const port = await listen(t, app);
  const client = browser(port);
  await client.call('/api/me');
  async function seed(index = 0, verified = true) {
    const password = fakeSecret();
    const data = store.read('accounts', emptyAccounts());
    const user = { id: `user-${index}`, tenant_id: tids[index], email: `user${index}@example.com`,
      password_hash: await hashPassword(password), auth_version: 1, email_verified_at: verified ? new Date(now()).toISOString() : null };
    data.users.push(user);
    data.tenants.push({ id: tids[index], name: '', plan: `plan-${index}`, hostname_limit: 3 + index, status: 'active' });
    store.write('accounts', data);
    const session = browser(port);
    await session.call('/api/me');
    const login = await session.call('/api/login', 'POST', { email: user.email, password });
    if (login.status !== 200) throw new Error('Fixture login failed');
    await session.call('/api/me');
    return { client: session, user, password };
  }
  return { app, dataDir, store, now, advance: (ms) => { clock += ms; }, messages, searches, port, client, seed, ...fake };
}
export const linkToken = (message) => new URLSearchParams(new URL(message.link).hash.slice(1)).get('token');
