import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createZone, mapHost } from '../src/onboard/store.js';
import { validateZone } from '../src/dns/validate-zone.js';
import { appendAudit, auditLogPath } from '../src/lib/audit.js';
import { syncZone, parsePopTargets, syncAfterOnboard } from '../src/dns/sync-coredns.js';
import { exportBind, readZone } from '../src/dns/store.js';

describe('coredns sync validation + audit', () => {
  let tmp;
  const prev = {};

  function snapEnv(keys) {
    for (const k of keys) prev[k] = process.env[k];
  }
  function restoreEnv() {
    for (const [k, v] of Object.entries(prev)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }

  before(() => {
    snapEnv(['ZONES_DIR', 'DATA_DIR', 'COREDNS_SYNC_ENABLED', 'COREDNS_SYNC_DRY_RUN', 'COREDNS_POP_TARGETS', 'COREDNS_ZONES_DIR', 'COREDNS_SSH_KEY', 'COREDNS_AUDIT_LOG', 'NS1_HOST', 'NS2_HOST']);
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-sync-'));
    process.env.ZONES_DIR = path.join(tmp, 'zones');
    process.env.DATA_DIR = path.join(tmp, 'data');
    process.env.COREDNS_ZONES_DIR = path.join(tmp, 'coredns-zones');
    process.env.COREDNS_AUDIT_LOG = path.join(tmp, 'data', 'audit', 'coredns-sync.jsonl');
    delete process.env.COREDNS_SYNC_ENABLED;
    delete process.env.COREDNS_SYNC_DRY_RUN;
    delete process.env.COREDNS_POP_TARGETS;
    delete process.env.COREDNS_SSH_KEY;
  });

  after(() => {
    restoreEnv();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  beforeEach(() => {
    process.env.COREDNS_SYNC_ENABLED = 'false';
    process.env.COREDNS_SYNC_DRY_RUN = 'false';
    delete process.env.COREDNS_POP_TARGETS;
  });

  it('validates SOA + ns1/ns2 and rejects empty zones', () => {
    const good = {
      records: [
        { name: '@', type: 'SOA', content: 'ns1.fastdognetworks.com. hostmaster.example. 1 3600 600 604800 300' },
        { name: '@', type: 'NS', content: 'ns1.fastdognetworks.com.' },
        { name: '@', type: 'NS', content: 'ns2.fastdognetworks.com.' },
      ],
    };
    assert.equal(validateZone(good).ok, true);
    assert.equal(validateZone({ records: [] }).ok, false);
    assert.ok(validateZone({ records: [{ name: '@', type: 'A', content: '1.2.3.4' }] }).errors.includes('missing_soa'));
    const missingNs2 = {
      records: [
        { name: '@', type: 'SOA', content: 'ns1.fastdognetworks.com. hostmaster.example. 1 3600 600 604800 300' },
        { name: '@', type: 'NS', content: 'ns1.fastdognetworks.com.' },
      ],
    };
    assert.ok(validateZone(missingNs2).errors.some((e) => e.startsWith('missing_ns:ns2')));
  });

  it('appends mode-safe JSONL audit events', () => {
    const r = appendAudit({ zone: 'audit.example', action: 'test', pops: [], success: true });
    assert.equal(r.ok, true);
    const file = auditLogPath();
    assert.ok(fs.existsSync(file));
    const line = fs.readFileSync(file, 'utf8').trim().split('\n').at(-1);
    const event = JSON.parse(line);
    assert.equal(event.zone, 'audit.example');
    assert.equal(event.success, true);
    assert.ok(event.ts);
    assert.equal(fs.statSync(file).mode & 0o777, 0o640);
  });

  it('parses pop targets', () => {
    assert.deepEqual(parsePopTargets('ns1=157.230.57.32,ns2=2.29.58.90'), [
      { name: 'ns1', host: '157.230.57.32' },
      { name: 'ns2', host: '2.29.58.90' },
    ]);
    assert.deepEqual(parsePopTargets(''), []);
  });

  it('skips when sync disabled and still succeeds after create-zone', () => {
    process.env.COREDNS_SYNC_ENABLED = 'false';
    const created = createZone({ zone: 'skip.example' });
    assert.equal(created.coredns_sync.ok, true);
    assert.equal(created.coredns_sync.skipped, true);
    assert.ok(readZone('skip.example'));
  });

  it('dry-run validates and audits without requiring PoP SSH', () => {
    process.env.COREDNS_SYNC_ENABLED = 'true';
    process.env.COREDNS_SYNC_DRY_RUN = 'true';
    process.env.COREDNS_POP_TARGETS = 'ns1=157.230.57.32,ns2=2.29.58.90';
    createZone({ zone: 'dry.example' });
    const result = syncZone('dry.example', { action: 'test-dry' });
    assert.equal(result.ok, true);
    assert.equal(result.dry_run, true);
    assert.equal(result.validated, true);
    const audit = fs.readFileSync(process.env.COREDNS_AUDIT_LOG, 'utf8');
    assert.match(audit, /dry\.example/);
    assert.match(audit, /"dry_run":true/);
  });

  it('mock remote failure does not roll back map-host', () => {
    process.env.COREDNS_SYNC_ENABLED = 'true';
    process.env.COREDNS_SYNC_DRY_RUN = 'false';
    process.env.COREDNS_POP_TARGETS = 'ns1=127.0.0.1';
    process.env.COREDNS_SSH_KEY = path.join(tmp, 'missing-key');
    createZone({ zone: 'fail.example', edge_ip: '192.0.2.10' });
    const mapped = mapHost({ zone: 'fail.example', hostname: 'app.fail.example' });
    assert.ok(readZone('fail.example').records.some((r) => r.name === 'app' && r.type === 'A'));
    assert.equal(mapped.coredns_sync.ok, false);
    assert.ok(mapped.coredns_sync.error);
    const bind = exportBind('fail.example');
    assert.ok(validateZone(bind, { zone: 'fail.example' }).ok);
  });

  it('syncAfterOnboard never throws', () => {
    assert.doesNotThrow(() => syncAfterOnboard('missing-zone-xyz', 'test'));
    const r = syncAfterOnboard('missing-zone-xyz', 'test');
    assert.equal(r.ok, false);
  });
});