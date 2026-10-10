import { describe, it, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

describe('hostname attach onboarding', () => {
  let tmp;
  let attachModule;
  let store;

  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-attach-'));
    process.env.ZONES_DIR = path.join(tmp, 'zones');
    process.env.DATA_DIR = path.join(tmp, 'data');
    process.env.INVITE_REQUIRED = 'false';
    process.env.ATTACH_TARGET = 'attach.fastdognetworks.com';
    process.env.EDGE_PUBLIC_IP = '157.230.57.32';
    attachModule = await import('../src/onboard/attach.js');
    store = await import('../src/onboard/store.js');
  });

  after(() => {
    delete process.env.ZONES_DIR;
    delete process.env.DATA_DIR;
    delete process.env.INVITE_REQUIRED;
    delete process.env.ATTACH_TARGET;
    delete process.env.EDGE_PUBLIC_IP;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('attaches a hostname with pending status', () => {
    const result = attachModule.attachHost({ hostname: 'app.example.com' });
    assert.equal(result.hostname, 'app.example.com');
    assert.equal(result.status, 'pending');
    assert.ok(result.created_at);
    assert.equal(result.cname_target, 'attach.fastdognetworks.com');
    assert.ok(result.cname_instructions.includes('CNAME'));
  });

  it('returns existing pending attachment without error', () => {
    const result = attachModule.attachHost({ hostname: 'app.example.com' });
    assert.equal(result.hostname, 'app.example.com');
    assert.equal(result.status, 'pending');
  });

  it('lists attached hostnames', () => {
    attachModule.attachHost({ hostname: 'second.example.com' });
    const hosts = attachModule.listAttachedHosts();
    assert.ok(Array.isArray(hosts));
    assert.equal(hosts.length, 2);
    assert.ok(hosts.some((h) => h.hostname === 'app.example.com'));
    assert.ok(hosts.some((h) => h.hostname === 'second.example.com'));
  });

  it('rejects invalid hostname', () => {
    assert.throws(() => attachModule.attachHost({ hostname: '' }), /invalid_domain/);
    assert.throws(() => attachModule.attachHost({ hostname: 'not-a-domain' }), /invalid_domain/);
  });

  it('generates CNAME instructions', () => {
    const instructions = attachModule.cnameInstructions('test.example.com');
    assert.equal(instructions.cname_target, 'attach.fastdognetworks.com');
    assert.ok(instructions.cname_instructions.includes('test.example.com'));
    assert.ok(instructions.cname_instructions.includes('CNAME'));
  });

  it('adds apex note for apex domains', () => {
    const instructions = attachModule.cnameInstructions('example.com');
    assert.ok(instructions.apex_note);
    assert.ok(instructions.apex_note.includes('apex'));
  });

  it('generates caddy block for hostname', () => {
    const block = attachModule.generateCaddyBlock('app.customer.com');
    assert.ok(block.includes('app.customer.com'));
    assert.ok(block.includes('reverse_proxy localhost:8787'));
    assert.ok(block.includes('import fdlog app.customer.com'));
    assert.ok(!/\blog\s*\{/.test(block), 'no bare log block: it would record the tunnel token and query strings');
    assert.ok(!block.includes('/var/log/caddy'));
  });

  it('detaches a hostname', () => {
    const result = attachModule.detachHost({ hostname: 'second.example.com' });
    assert.equal(result.hostname, 'second.example.com');
    assert.equal(result.detached, true);
    assert.equal(result.previous_status, 'pending');
    const hosts = attachModule.listAttachedHosts();
    assert.ok(!hosts.some((h) => h.hostname === 'second.example.com'));
  });

  it('throws when detaching non-existent hostname', () => {
    assert.throws(() => attachModule.detachHost({ hostname: 'notattached.example.com' }), /hostname_not_attached/);
  });

  it('gets attached host details', () => {
    const host = attachModule.getAttachedHost('app.example.com');
    assert.equal(host.hostname, 'app.example.com');
    assert.equal(host.status, 'pending');
  });

  it('throws when getting non-existent host', () => {
    assert.throws(() => attachModule.getAttachedHost('notattached.example.com'), /hostname_not_attached/);
  });
});

describe('DNS verification logic', () => {
  let attachModule;

  before(async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-dns-'));
    process.env.ZONES_DIR = path.join(tmp, 'zones');
    process.env.DATA_DIR = path.join(tmp, 'data');
    process.env.ATTACH_TARGET = 'attach.fastdognetworks.com';
    process.env.ALT_ATTACH_TARGET = 'edge.fastdognetworks.com';
    process.env.EDGE_PUBLIC_IP = '157.230.57.32';
    attachModule = await import('../src/onboard/attach.js');
  });

  after(() => {
    delete process.env.ZONES_DIR;
    delete process.env.DATA_DIR;
    delete process.env.ATTACH_TARGET;
    delete process.env.ALT_ATTACH_TARGET;
    delete process.env.EDGE_PUBLIC_IP;
  });

  it('checkDnsVerification returns expected structure for non-existent domain', async () => {
    const result = await attachModule.checkDnsVerification('nonexistent.invalid.test');
    assert.equal(result.verified, false);
    assert.ok(result.error);
  });

  it('verification fails for hostname not attached', async () => {
    await assert.rejects(
      attachModule.verifyHost({ hostname: 'notattached.example.com' }),
      /hostname_not_attached/
    );
  });
});

describe('attach API integration', () => {
  let tmp;
  let server;
  let base;

  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-attach-api-'));
    process.env.NODE_ENV = 'test';
    process.env.ZONES_DIR = path.join(tmp, 'zones');
    process.env.DATA_DIR = path.join(tmp, 'data');
    process.env.INVITE_REQUIRED = 'false';
    process.env.AGENT_TOKEN = 'attach-test-token';
    process.env.ATTACH_TARGET = 'attach.fastdognetworks.com';
    process.env.EDGE_PUBLIC_IP = '157.230.57.32';

    const { server: edgeServer } = await import('../src/edge/server.js');
    server = edgeServer;
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
    delete process.env.NODE_ENV;
    delete process.env.ZONES_DIR;
    delete process.env.DATA_DIR;
    delete process.env.INVITE_REQUIRED;
    delete process.env.AGENT_TOKEN;
    delete process.env.ATTACH_TARGET;
    delete process.env.EDGE_PUBLIC_IP;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  const post = (url, body, token = 'attach-test-token') =>
    fetch(`${base}${url}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-fastdog-token': token },
      body: JSON.stringify(body),
    });

  const get = (url, token = 'attach-test-token') =>
    fetch(`${base}${url}`, {
      headers: { 'x-fastdog-token': token },
    });

  const del = (url, token = 'attach-test-token') =>
    fetch(`${base}${url}`, {
      method: 'DELETE',
      headers: { 'x-fastdog-token': token },
    });

  it('rejects attach without token', async () => {
    const res = await post('/_fastdog/onboard/attach-host', { hostname: 'test.example.com' }, 'wrong');
    assert.equal(res.status, 401);
  });

  it('attaches hostname via API', async () => {
    const res = await post('/_fastdog/onboard/attach-host', { hostname: 'api.example.com' });
    assert.equal(res.status, 201);
    const data = await res.json();
    assert.equal(data.hostname, 'api.example.com');
    assert.equal(data.status, 'pending');
    assert.ok(data.cname_target);
    assert.ok(data.cname_instructions);
  });

  it('lists attached hosts via API', async () => {
    const res = await get('/_fastdog/onboard/attached-hosts');
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data.hosts));
    assert.ok(data.hosts.some((h) => h.hostname === 'api.example.com'));
  });

  it('gets single attached host via API', async () => {
    const res = await get('/_fastdog/onboard/attached-hosts/api.example.com');
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.hostname, 'api.example.com');
    assert.equal(data.status, 'pending');
  });

  it('verify-host returns pending for unverifiable DNS', async () => {
    const res = await post('/_fastdog/onboard/verify-host', { hostname: 'api.example.com' });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.verified, false);
    assert.equal(data.status, 'pending');
    assert.ok(data.error);
  });

  it('detaches hostname via API', async () => {
    const res = await del('/_fastdog/onboard/attached-hosts/api.example.com');
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.detached, true);
  });

  it('returns 404 for non-existent attached host', async () => {
    const res = await get('/_fastdog/onboard/attached-hosts/notattached.example.com');
    assert.equal(res.status, 404);
  });

  it('rejects attach for static route conflict', async () => {
    const res = await post('/_fastdog/onboard/attach-host', { hostname: 'demo.fastdog.local' });
    assert.equal(res.status, 409);
    const data = await res.json();
    assert.equal(data.error, 'static_route_conflict');
  });
});

describe('fail-closed behavior', () => {
  let tmp;
  let attachModule;

  before(async () => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-failclosed-'));
    process.env.ZONES_DIR = path.join(tmp, 'zones');
    process.env.DATA_DIR = path.join(tmp, 'data');
    process.env.ATTACH_TARGET = 'attach.fastdognetworks.com';
    process.env.EDGE_PUBLIC_IP = '157.230.57.32';
    attachModule = await import('../src/onboard/attach.js');
  });

  after(() => {
    delete process.env.ZONES_DIR;
    delete process.env.DATA_DIR;
    delete process.env.ATTACH_TARGET;
    delete process.env.EDGE_PUBLIC_IP;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it('pending attachment does not add to tunnel_hosts', () => {
    attachModule.attachHost({ hostname: 'pending.example.com' });
    const tunnelHostsFile = path.join(tmp, 'data', 'tunnel_hosts.json');
    if (fs.existsSync(tunnelHostsFile)) {
      const hosts = JSON.parse(fs.readFileSync(tunnelHostsFile, 'utf8'));
      assert.ok(!hosts.includes('pending.example.com'));
    }
  });

  it('pending attachment does not issue credential', () => {
    const attachment = attachModule.getAttachedHost('pending.example.com');
    assert.equal(attachment.status, 'pending');
    const credentialsFile = path.join(tmp, 'data', 'agent-credentials.json');
    if (fs.existsSync(credentialsFile)) {
      const creds = JSON.parse(fs.readFileSync(credentialsFile, 'utf8'));
      assert.ok(!creds.some((c) => c.hostname === 'pending.example.com'));
    }
  });

  it('verification failure keeps attachment pending', async () => {
    const result = await attachModule.verifyHost({ hostname: 'pending.example.com' });
    assert.equal(result.verified, false);
    assert.equal(result.status, 'pending');
    const attachment = attachModule.getAttachedHost('pending.example.com');
    assert.equal(attachment.status, 'pending');
  });
});
