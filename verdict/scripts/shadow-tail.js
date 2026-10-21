#!/usr/bin/env node
import { loadHostingAsns, asnDb } from '../src/asn/lookup.js';
import { scoreAccessLogLine, createShadowWriter } from '../src/shadow/score.js';
import { offsetsFile, loadOffsets, saveOffsets, consumeLog } from '../src/shadow/offsets.js';

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
// Offsets survive restarts (src/shadow/offsets.js): resume, or start at the end of a log never seen before.
const offsetsPath = offsetsFile({ ...process.env, VERDICT_SHADOW_FILE: outFile });
const saved = await loadOffsets(offsetsPath);
const offsets = new Map(); // path -> {ino, offset}; ino null = absent when first polled
let offsetsDirty = false;
const writeRow = createShadowWriter(outFile, { maxBytes });

async function consume(path) {
  const prev = offsets.has(path) ? offsets.get(path) : saved[path];
  let next;
  try {
    next = await consumeLog(path, prev, async line => {
      const scored = await scoreAccessLogLine(line, { hosting });
      if (scored) await writeRow(scored);
      await new Promise(r => setImmediate(r));
    });
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    if (!offsets.has(path)) offsets.set(path, { ino: null, offset: 0 }); // appears later: read from 0
    return;
  }
  if (prev?.ino !== next.ino || prev?.offset !== next.offset) offsetsDirty = true;
  offsets.set(path, next);
}

console.log(JSON.stringify({ shadow_tail: true, logs: logPaths, out: logPaths.length ? outFile : null, offsets: logPaths.length ? offsetsPath : null, customer: Boolean(customer) }));
for (;;) {
  if (logPaths.length) await writeRow.trim();
  for (const p of logPaths) {
    try { await consume(p); } catch (e) { console.error('tail_error', p, e.message); }
  }
  if (offsetsDirty) {
    await writeRow.ready();
    const state = Object.fromEntries([...offsets].filter(([, v]) => v.ino !== null));
    try { await saveOffsets(offsetsPath, state); offsetsDirty = false; } catch (e) { console.error('offsets_error', e.code || e.message); }
  }
  if (customer) { try { await customer.poll(); } catch (e) { console.error('customer_tail_error', e.message); } }
  await new Promise(r => setTimeout(r, pollMs));
}
