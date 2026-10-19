import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, stat, readdir, rm, mkdir, open } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createShadowWriter, shadowRetentionDays, pruneShadowSummaries } from '../src/shadow/retention.js';
import { writeShadowSummary } from '../src/shadow/summary.js';

const time = Date.parse('2026-10-19T12:00:00Z');
const DAY = 86400000;
const row = (age, id) => ({ ts: new Date(time - age * DAY).toISOString(), id });
const lines = rows => rows.map(r => JSON.stringify(r) + '\n').join('');
async function fixture(t) {
  const dir = await mkdtemp(join(tmpdir(), 'shadow-retention-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { dir, file: join(dir, 'shadow.jsonl') };
}

test('retention defaults, alias, precedence and seven-day floor', () => {
  for (const value of [undefined, '', 'bad', 'NaN', 'Infinity']) {
    assert.equal(shadowRetentionDays({ VERDICT_SHADOW_MAX_AGE_DAYS: value }), 30);
  }
  for (const value of ['0', '-1', '3']) assert.equal(shadowRetentionDays({ SHADOW_RETENTION_DAYS: value }), 7);
  assert.equal(shadowRetentionDays({ SHADOW_RETENTION_DAYS: '14' }), 14);
  assert.equal(shadowRetentionDays({ VERDICT_SHADOW_MAX_AGE_DAYS: '20', SHADOW_RETENTION_DAYS: '14' }), 20);
});

test('age trim atomically replaces file, preserves rows and private mode', async t => {
  const { dir, file } = await fixture(t);
  const kept = [row(29, 'keep'), row(1, 'recent')];
  const original = lines([row(31, 'old'), kept[0], row(30, 'boundary'), kept[1]]) + 'invalid\n{}\n';
  await writeFile(file, original);
  const handle = await open(file, 'r');
  try {
    const writer = createShadowWriter(file, { now: () => time });
    await writer.trim();
    assert.equal(await readFile(file, 'utf8'), lines(kept));
    assert.equal(await handle.readFile('utf8'), original); // Old inode is intact.
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.deepEqual(await readdir(dir), ['shadow.jsonl']);
    await writer(row(40, 'expired-input'));
    assert.equal(await readFile(file, 'utf8'), lines(kept));
  } finally { await handle.close(); }
});

test('floor keeps six-day rows and idle maintenance expires them', async t => {
  const { file } = await fixture(t);
  let clock = time;
  await writeFile(file, lines([row(8, 'old'), row(6, 'keep')]));
  const writer = createShadowWriter(file, { maxAgeDays: 1, now: () => clock });
  await writer.trim();
  assert.equal(await readFile(file, 'utf8'), lines([row(6, 'keep')]));
  clock += 2 * DAY;
  await writer.trim();
  assert.equal(await readFile(file, 'utf8'), '');
});

test('size removes oldest timestamps first, including recent rows only as necessary', async t => {
  const { file } = await fixture(t);
  const recent = row(1, 'aa');
  const old = row(20, 'bb');
  const incoming = row(0, 'cc');
  const cap = Buffer.byteLength(lines([recent, incoming]));
  await writeFile(file, lines([recent, old, row(31, 'dd')]));
  const writer = createShadowWriter(file, { maxBytes: cap, now: () => time });
  await writer(incoming);
  assert.equal(await readFile(file, 'utf8'), lines([recent, incoming]));
  await writer(row(0, 'ee'));
  assert.equal(await readFile(file, 'utf8'), lines([incoming, row(0, 'ee')]));
  await writer(row(29, 'ff')); // Late-arriving history must not displace newer rows.
  assert.equal(await readFile(file, 'utf8'), lines([incoming, row(0, 'ee')]));
  await writer(row(0, 'x'.repeat(cap)));
  assert.ok((await stat(file)).size <= cap);
});

test('concurrent UTF-8 writes are serialized and retain complete shadow rows', async t => {
  const { file } = await fixture(t);
  const records = Array.from({ length: 20 }, (_, i) => ({ ...row(0, i), host: 'example.test', ua: 'é' }));
  const cap = Buffer.byteLength(lines(records.slice(-3)));
  const writer = createShadowWriter(file, { maxBytes: cap, now: () => time });
  await Promise.all(records.map(writer));
  await writer.ready();
  assert.equal(await readFile(file, 'utf8'), lines(records.slice(-3)));
});

test('summary prune uses dates, retention floor and exact filenames', async t => {
  const { dir } = await fixture(t);
  const names = ['shadow-summary-20261011.json', 'shadow-summary-20261013.json', 'shadow-summary-20260901.json', 'other.json', 'shadow-summary-20260230.json'];
  await Promise.all(names.map(name => writeFile(join(dir, name), '{}')));
  await mkdir(join(dir, 'shadow-summary-20260101.json'));
  await pruneShadowSummaries(dir, { maxAgeDays: 1, now: () => time });
  assert.deepEqual((await readdir(dir)).sort(), ['other.json', 'shadow-summary-20260101.json', 'shadow-summary-20260230.json', 'shadow-summary-20261013.json']);
});

test('summary writer prunes expired summaries', async t => {
  const { dir, file } = await fixture(t);
  await writeFile(file, '');
  await writeFile(join(dir, 'shadow-summary-20000101.json'), '{}');
  const { out } = await writeShadowSummary(file, dir);
  assert.ok((await readdir(dir)).includes(out.split('/').pop()));
  assert.ok(!(await readdir(dir)).includes('shadow-summary-20000101.json'));
});

test('bad paths warn and fail open; writer recovers after I/O failure', async t => {
  const { dir, file } = await fixture(t);
  const warnings = [];
  await mkdir(file);
  const writer = createShadowWriter(file, { now: () => time, warn: code => warnings.push(code) });
  await writer.trim();
  await writer(row(0, 'failed'));
  await pruneShadowSummaries(join(dir, 'missing'), { warn: code => warnings.push(code) });
  assert.ok(warnings.length >= 3);
  await rm(file, { recursive: true });
  await writer(row(0, 'recovered'));
  assert.equal(await readFile(file, 'utf8'), lines([row(0, 'recovered')]));
});
