#!/usr/bin/env node
import { stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { loadHostingAsns, asnDb } from '../src/asn/lookup.js';
import { scoreAccessLogLine, createShadowWriter } from '../src/shadow/score.js';

import { createCountStore, createCustomerTail, excludedHosts } from '../src/shadow/customer.js';

// VERDICT_SHADOW_LOGS="" (set but empty) turns the first-party scorer off; customer mode is separate.
const logPaths = (process.env.VERDICT_SHADOW_LOGS ?? '/var/log/caddy/access-apex.json,/var/log/caddy/access-verdict-demo.json')
  .split(',').map(s => s.trim()).filter(Boolean);
const outFile = process.env.VERDICT_SHADOW_FILE || 'data/shadow.jsonl';
const asnFile = process.env.VERDICT_ASN_FILE || '';
const maxBytes = Number(process.env.VERDICT_SHADOW_MAX_BYTES ?? 10 * 1024 * 1024);
const pollMs = Math.max(500, Number(process.env.VERDICT_SHADOW_POLL_MS || 2000));

const hosting = loadHostingAsns();
if (asnFile) {
  try { await asnDb.loadFile(asnFile); console.log(JSON.stringify({ asn_rows: asnDb.rows })); }
  catch (e) { console.warn('asn skip:', e.message); }
}

const customerDir = process.env.VERDICT_SHADOW_CUSTOMER_DIR || '';
const countsFile = process.env.VERDICT_SHADOW_COUNTS_FILE || '';
let customer = null;
if (customerDir && countsFile) {
  const store = createCountStore(countsFile);
  await store.load();
  customer = createCustomerTail({ logDir: customerDir, store, hosting, exclude: excludedHosts() });
}
const offsets = new Map();
const writeRow = createShadowWriter(outFile, { maxBytes });

async function consume(path) {
  let size = 0;
  try { size = (await stat(path)).size; } catch { return; }
  let start = offsets.get(path) || 0;
  if (size < start) start = 0;
  if (size <= start) return;
  const stream = createReadStream(path, { encoding: 'utf8', start });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) {
    const scored = await scoreAccessLogLine(line, { hosting });
    if (scored) await writeRow(scored);
    await new Promise(r => setImmediate(r));
  }
  offsets.set(path, size);
}

console.log(JSON.stringify({ shadow_tail: true, logs: logPaths, out: logPaths.length ? outFile : null, customer: Boolean(customer) }));
for (;;) {
  if (logPaths.length) await writeRow.trim();
  for (const p of logPaths) {
    try { await consume(p); } catch (e) { console.error('tail_error', p, e.message); }
  }
  if (customer) { try { await customer.poll(); } catch (e) { console.error('customer_tail_error', e.message); } }
  await new Promise(r => setTimeout(r, pollMs));
}
