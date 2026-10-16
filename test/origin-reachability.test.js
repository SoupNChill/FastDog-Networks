import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { EventEmitter } from 'node:events';
import { isCloudflareProxyIp, checkDnsVerification } from '../src/onboard/attach.js';
import { startHeartbeat } from '../agent/heartbeat.js';

process.env.FASTDOG_AGENT_NO_MAIN = '1';
const { probeOrigin } = await import('../agent/index.js');

test('Cloudflare proxy addresses are recognised; others are not', () => {
  for (const ip of ['104.16.1.1', '172.67.10.10', '188.114.97.3', '162.159.0.1']) assert.equal(isCloudflareProxyIp(ip), true, ip);
  for (const ip of ['192.0.2.10', '8.8.8.8', '203.0.113.5', 'not-an-ip', '104.32.0.1']) assert.equal(isCloudflareProxyIp(ip), false, ip);
});

test('a proxied CNAME gets dns_proxied; correct and missing records keep their results', async () => {
  const noData = () => Object.assign(new Error('no data'), { code: 'ENODATA' });
  const resolver = (cname, a) => ({ async resolveCname() { if (!cname) throw noData(); return cname; }, async resolve4() { if (!a) throw noData(); return a; } });
  const opts = { attachTarget: 'attach.example-edge.test', altAttachTarget: 'alt.example-edge.test', edgePublicIp: '192.0.2.10' };
  assert.equal((await checkDnsVerification('app.example.test', { ...opts, resolver: resolver(null, ['104.21.5.6', '172.67.1.2']) })).error, 'dns_proxied');
  assert.equal((await checkDnsVerification('app.example.test', { ...opts, resolver: resolver(['attach.example-edge.test']) })).verified, true);
  assert.equal((await checkDnsVerification('app.example.test', { ...opts, resolver: resolver(null, null) })).error, 'no_dns_record');
  assert.equal((await checkDnsVerification('app.example.test', { ...opts, resolver: resolver(null, ['203.0.113.5']) })).error, 'a_wrong_target');
});

test('agent probe reports a listening app as reachable and a closed port as not', async (t) => {
  let bodySeen = false;
  const server = http.createServer((req, res) => { res.end('private app content'); bodySeen = true; });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const { port } = server.address();
  assert.equal(await probeOrigin(`http://127.0.0.1:${port}`), true);
  assert.equal(bodySeen, true);
  const closed = http.createServer();
  await new Promise((resolve) => closed.listen(0, '127.0.0.1', resolve));
  const closedPort = closed.address().port;
  await new Promise((resolve) => closed.close(resolve));
  assert.equal(await probeOrigin(`http://127.0.0.1:${closedPort}`, { timeoutMs: 500 }), false);
  assert.equal(await probeOrigin('not a url'), false);
});

test('heartbeat pings carry only the origin status fields', async () => {
  const ws = Object.assign(new EventEmitter(), { readyState: 1, sent: [], send(data) { this.sent.push(JSON.parse(data)); }, terminate() {} });
  const stop = startHeartbeat(ws, { intervalMs: 5, status: () => ({ origin_reachable: false, origin_checked_at: '2026-01-01T00:00:00.000Z', type: 'spoof' }) });
  await new Promise((resolve) => setTimeout(resolve, 20));
  stop();
  assert.deepEqual(ws.sent[0], { origin_reachable: false, origin_checked_at: '2026-01-01T00:00:00.000Z', type: 'ping' });
});

test('edge tenant agent status passes origin reachability through, null for older agents', async (t) => {
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { createClaims } = await import('../src/internal/claims.js');
  const dir = mkdtempSync(join(tmpdir(), 'claims-origin-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'tenant_hostnames.json'), JSON.stringify([{ tenant_id: 't_a', hostname: 'app.example.test', status: 'active' }]));
  let agent = { connected: true, localUpstream: 'http://127.0.0.1:5000', originReachable: false, originCheckedAt: '2026-01-01T00:00:00.000Z' };
  const claims = createClaims({ dataDir: dir, attachTarget: 'attach.example-edge.test', altAttachTarget: 'alt.example-edge.test', registry: { getAgentByHost: () => agent, closeHost() {} } }, () => {});
  assert.deepEqual(pickOrigin(claims.agent('t_a', 'app.example.test')), { origin_reachable: false, origin_checked_at: '2026-01-01T00:00:00.000Z', origin_address: '127.0.0.1:5000' });
  agent = { connected: true, localUpstream: 'http://127.0.0.1:5000' };
  assert.deepEqual(pickOrigin(claims.agent('t_a', 'app.example.test')), { origin_reachable: null, origin_checked_at: null, origin_address: '127.0.0.1:5000' });
  assert.throws(() => claims.agent('t_b', 'app.example.test'));
});
const pickOrigin = ({ origin_reachable, origin_checked_at, origin_address }) => ({ origin_reachable, origin_checked_at, origin_address });
