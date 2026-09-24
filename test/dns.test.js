import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  listZones,
  readZone,
  writeZone,
  upsertRecord,
  deleteRecord,
  exportBind,
  zonesDir,
} from '../src/dns/store.js';

describe('dns store', () => {
  let tmp;

  before(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-zones-'));
    process.env.ZONES_DIR = tmp;
    writeZone('example.test', {
      ttl_default: 60,
      records: [{ name: '@', type: 'A', content: '127.0.0.1', ttl: 60 }],
    });
  });

  after(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
    delete process.env.ZONES_DIR;
  });

  it('lists and reads zones', () => {
    assert.equal(zonesDir(), tmp);
    assert.deepEqual(listZones(), ['example.test']);
    const z = readZone('example.test');
    assert.equal(z.records[0].content, '127.0.0.1');
  });

  it('upserts and deletes records', () => {
    upsertRecord('example.test', { name: 'www', type: 'CNAME', content: 'example.test.', ttl: 60 });
    let z = readZone('example.test');
    assert.ok(z.records.some((r) => r.name === 'www'));
    deleteRecord('example.test', { name: 'www', type: 'CNAME' });
    z = readZone('example.test');
    assert.ok(!z.records.some((r) => r.name === 'www'));
  });

  it('exports BIND zone text', () => {
    const text = exportBind('example.test');
    assert.match(text, /\$ORIGIN example\.test\./);
    assert.match(text, /IN\tA\t127\.0\.0\.1/);
  });

  it('reads shipped trysummitlease stub', () => {
    const repoZones = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../zones');
    process.env.ZONES_DIR = repoZones;
    const z = readZone('trysummitlease.com');
    assert.ok(z);
    assert.equal(z.zone, 'trysummitlease.com');
    assert.ok(z.records.some((r) => r.type === 'TXT'));
    process.env.ZONES_DIR = tmp;
  });

  it('reads fastdognetworks.com zone with required records', () => {
    const repoZones = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../zones');
    process.env.ZONES_DIR = repoZones;
    const z = readZone('fastdognetworks.com');
    assert.ok(z, 'fastdognetworks.com zone should exist');
    assert.equal(z.zone, 'fastdognetworks.com');

    // SOA record required for authoritative DNS
    assert.ok(z.records.some((r) => r.type === 'SOA'), 'must have SOA record');
    const soa = z.records.find((r) => r.type === 'SOA');
    assert.match(soa.content, /ns1\.fastdognetworks\.com\./);

    // NS record required
    assert.ok(z.records.some((r) => r.type === 'NS'), 'must have NS record');
    const ns = z.records.find((r) => r.type === 'NS');
    assert.equal(ns.content, 'ns1.fastdognetworks.com.');

    // A records for ns1, edge, and apex
    const aRecords = z.records.filter((r) => r.type === 'A');
    assert.ok(aRecords.length >= 3, 'must have A records for ns1, edge, and apex');
    assert.ok(aRecords.some((r) => r.name === 'ns1'), 'must have ns1 A record');
    assert.ok(aRecords.some((r) => r.name === 'edge'), 'must have edge A record');
    assert.ok(aRecords.some((r) => r.name === '@'), 'must have apex A record');

    // ns2 is the separate Hetzner DNS PoP; other A records use the edge PoP.
    for (const r of aRecords) {
      assert.equal(r.content, r.name === 'ns2' ? '2.29.58.90' : '157.230.57.32', `${r.name} A record should point to its PoP IP`);
    }

    process.env.ZONES_DIR = tmp;
  });

  it('exports fastdognetworks.com as valid BIND zone', () => {
    const repoZones = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../zones');
    process.env.ZONES_DIR = repoZones;
    const text = exportBind('fastdognetworks.com');
    assert.ok(text, 'BIND export should return content');

    // Check BIND format basics
    assert.match(text, /\$ORIGIN fastdognetworks\.com\./, 'must have $ORIGIN');
    assert.match(text, /\$TTL/, 'must have $TTL');

    // Check records are present
    assert.match(text, /IN\s+SOA\s+ns1\.fastdognetworks\.com\./, 'must have SOA');
    assert.match(text, /IN\s+NS\s+ns1\.fastdognetworks\.com\./, 'must have NS');
    assert.match(text, /ns1\s+\d+\s+IN\s+A\s+157\.230\.57\.32/, 'must have ns1 A');
    assert.match(text, /edge\s+\d+\s+IN\s+A\s+157\.230\.57\.32/, 'must have edge A');

    process.env.ZONES_DIR = tmp;
  });
});
