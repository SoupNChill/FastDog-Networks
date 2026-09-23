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
});
