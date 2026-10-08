#!/usr/bin/env node
import { stat, appendFile, mkdir } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { dirname } from 'node:path';
import { loadHostingAsns, asnDb } from '../src/asn/lookup.js';
import { scoreAccessLogLine } from '../src/shadow/score.js';

const logPaths = (process.env.VERDICT_SHADOW_LOGS || '/var/log/caddy/access-apex.json,/var/log/caddy/access-verdict-demo.json')
  .split(',').map(s => s.trim()).filter(Boolean);
const outFile = process.env.VERDICT_SHADOW_FILE || 'data/shadow.jsonl';
const asnFile = process.env.VERDICT_ASN_FILE || '';
const maxBytes = Number(process.env.VERDICT_SHADOW_MAX_BYTES || 10 * 1024 * 1024);
const pollMs = Math.max(500, Number(process.env.VERDICT_SHADOW_POLL_MS || 2000));

const hosting = loadHostingAsns();
if (asnFile) {
  try { await asnDb.loadFile(asnFile); console.log(JSON.stringify({ asn_rows: asnDb.rows })); }
  catch (e) { console.warn('asn skip:', e.message); }
}

await mkdir(dirname(outFile), { recursive: true });
const offsets = new Map();
let outSize = 0;
try { outSize = (await stat(outFile)).size; } catch { outSize = 0; }

async function writeRow(row) {
  const line = JSON.stringify(row) + '\n';
  const n = Buffer.byteLength(line);
  if (maxBytes && outSize + n > maxBytes) {
    const { truncate } = await import('node:fs/promises');
    await truncate(outFile, 0);
    outSize = 0;
  }
  await appendFile(outFile, line, { mode: 0o600 });
  outSize += n;
}

async function consume(path) {
  let size = 0;
  try { size = (await stat(path)).size; } catch { return; }
  let start = offsets.get(path) || 0;
  if (size < start) start = 0;
  if (size <= start) return;
  const stream = createReadStream(path, { encoding: 'utf8', start });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    const scored = scoreAccessLogLine(line, { hosting });
    if (scored) await writeRow(scored);
    await new Promise(r => setImmediate(r));
  }
  offsets.set(path, size);
}

console.log(JSON.stringify({ shadow_tail: true, logs: logPaths, out: outFile }));
for (;;) {
  for (const p of logPaths) {
    try { await consume(p); } catch (e) { console.error('tail_error', p, e.message); }
  }
  await new Promise(r => setTimeout(r, pollMs));
}
