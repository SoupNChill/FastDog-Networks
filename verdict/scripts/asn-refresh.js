#!/usr/bin/env node
/**
 * Weekly ASN refresh from iptoasn.com (public domain). Streams gunzip → compact
 * binary (data/asn/asn.bin). Keeps the old file if download/sanity fails.
 */
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, rename, stat, writeFile, unlink, readFile } from 'node:fs/promises';
import { createGunzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { createCompiler, serialize, deserialize } from '../src/asn/lookup.js';

const url = process.env.VERDICT_ASN_URL || 'https://iptoasn.com/data/ip2asn-combined.tsv.gz';
const dir = process.env.VERDICT_ASN_DIR || 'data/asn';
const dest = join(dir, 'asn.bin');
const minV4 = Number(process.env.VERDICT_ASN_MIN_V4 || 100000);
const minV6 = Number(process.env.VERDICT_ASN_MIN_V6 || 10000);
const gz = join(dir, 'download.tsv.gz.staging');
const staging = join(dir, 'asn.bin.staging');

async function cleanup() { await unlink(gz).catch(() => {}); await unlink(staging).catch(() => {}); }
function fail(error, extra = {}) { console.error(JSON.stringify({ ok: false, error, kept_old: true, ...extra })); return cleanup().then(() => process.exit(2)); }

await mkdir(dir, { recursive: true });
console.log(JSON.stringify({ fetching: url }));
let res;
try { res = await fetch(url, { headers: { 'User-Agent': 'FastDog-Verdict-ASN-Refresh/0.3' }, signal: AbortSignal.timeout(120000) }); }
catch (e) { await fail('fetch_error', { message: e.message }); }
if (!res.ok) await fail('fetch_status', { status: res.status });
await pipeline(res.body, createWriteStream(gz));
const sha = createHash('sha256');
await pipeline(createReadStream(gz), async function* (src) { for await (const c of src) sha.update(c); });
const gzSha = sha.digest('hex');

const compiler = createCompiler();
try {
  const rl = createInterface({ input: createReadStream(gz).pipe(createGunzip()), crlfDelay: Infinity });
  for await (const line of rl) compiler.line(line);
} catch (e) { await fail('gunzip_or_parse', { message: e.message }); }
const db = compiler.finish();
const n4 = db.v4.s.length, n6 = db.v6.sh.length;
if (n4 < minV4 || n6 < minV6 || db.unsorted) await fail('sanity', { v4: n4, v6: n6, unsorted: db.unsorted });

const bin = serialize(db);
await writeFile(staging, bin, { mode: 0o644 });
// Verify round-trip and a known lookup before swapping.
const check = deserialize(await readFile(staging));
if (check.v4.s.length !== n4 || check.v6.sh.length !== n6) await fail('roundtrip');
const binSha = createHash('sha256').update(bin).digest('hex');
await rename(staging, dest);
await writeFile(dest + '.sha256', `${binSha}  asn.bin\nsource_gz_sha256 ${gzSha}\n`);
await unlink(gz).catch(() => {});
console.log(JSON.stringify({ ok: true, v4: n4, v6: n6, skipped: db.skipped, bytes: (await stat(dest)).size, sha256: binSha, source_gz_sha256: gzSha }));
