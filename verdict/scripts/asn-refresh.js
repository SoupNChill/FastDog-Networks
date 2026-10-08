#!/usr/bin/env node
/**
 * Weekly ASN refresh from iptoasn.com (public domain). Keeps old file if new is bad.
 */
import { createWriteStream } from 'node:fs';
import { mkdir, rename, stat, readFile, writeFile, unlink } from 'node:fs/promises';
import { createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { createAsnDb } from '../src/asn/lookup.js';

const url = process.env.VERDICT_ASN_URL || 'https://iptoasn.com/data/ip2asn-combined.tsv.gz';
const destDir = process.env.VERDICT_ASN_DIR || 'data/asn';
const dest = join(destDir, 'ip2asn-combined.tsv');
const minRows = Number(process.env.VERDICT_ASN_MIN_ROWS || 100000);

await mkdir(destDir, { recursive: true });
const stagingGz = join(destDir, 'ip2asn-combined.tsv.gz.staging');
const stagingTsv = join(destDir, 'ip2asn-combined.tsv.staging');

console.log(JSON.stringify({ fetching: url }));
const res = await fetch(url, { headers: { 'User-Agent': 'FastDog-Verdict-ASN-Refresh/0.3' } });
if (!res.ok) throw new Error(`fetch_failed_${res.status}`);
await pipeline(res.body, createWriteStream(stagingGz));

await pipeline(
  (await import('node:fs')).createReadStream(stagingGz),
  createGunzip(),
  createWriteStream(stagingTsv),
);

const db = createAsnDb();
await db.loadFile(stagingTsv);
if (db.rows < minRows) {
  console.error(JSON.stringify({ error: 'sanity_failed', rows: db.rows, minRows, kept_old: true }));
  await unlink(stagingGz).catch(() => {});
  await unlink(stagingTsv).catch(() => {});
  process.exit(2);
}

const buf = await readFile(stagingTsv);
const sha = createHash('sha256').update(buf).digest('hex');
await rename(stagingTsv, dest);
await writeFile(dest + '.sha256', sha + '\n', { mode: 0o644 });
await unlink(stagingGz).catch(() => {});
const size = (await stat(dest)).size;
console.log(JSON.stringify({ ok: true, rows: db.rows, bytes: size, sha256: sha, dest }));
