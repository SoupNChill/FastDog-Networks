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
// Offsets survive restarts (src/shadow/offsets.js): resume, or start at the last complete line of a log
// never seen before. Only rows the writer acknowledged are checkpointed, every CHECKPOINT_LINES lines and
// at the end of each poll; a failed write stops that log and is retried from the same line next poll.
// Residual risk (accepted for this shadow-only, non-enforcing tailer): a crash after a row is appended but
// before its checkpoint is saved replays at most CHECKPOINT_LINES rows as duplicates on restart (exactly-once
// would need a transactional writer; trim() may rewrite the output mid-batch, so the output cannot simply be
// truncated back to a recorded size). Rows appended to a log after it rotates while the tailer is stopped
// are not read, since the old file can only be drained through a descriptor retained by a running tailer.
const offsetsPath = offsetsFile({ ...process.env, VERDICT_SHADOW_FILE: outFile });
const saved = await loadOffsets(offsetsPath);
const offsets = new Map(); // path -> {ino, offset, head}; ino null = absent when first polled
const handles = new Map(); // path -> retained descriptor, drained after a rotation
let offsetsDirty = false;
const writeRow = createShadowWriter(outFile, { maxBytes });

async function persistOffsets() {
  if (!offsetsDirty) return;
  const state = Object.fromEntries([...offsets].filter(([, v]) => v.ino !== null));
  try { await saveOffsets(offsetsPath, state); offsetsDirty = false; } catch (e) { console.error('offsets_error', e.code || 'IO_ERROR'); }
}

async function consume(path) {
  const prev = offsets.has(path) ? offsets.get(path) : saved[path];
  try {
    await consumeLog(path, prev, async line => {
      const scored = await scoreAccessLogLine(line, { hosting });
      if (scored && !(await writeRow(scored))) throw Object.assign(new Error('shadow write failed'), { code: 'SHADOW_WRITE_FAILED' });
      await new Promise(r => setImmediate(r));
    }, {
      handles,
      checkpoint: async next => {
        const last = offsets.get(path) ?? prev;
        if (last?.ino !== next.ino || last?.offset !== next.offset || last?.head !== next.head) offsetsDirty = true;
        offsets.set(path, next);
        await persistOffsets();
      },
    });
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    if (!offsets.has(path)) offsets.set(path, { ino: null, offset: 0 }); // appears later: read from 0
  }
}

console.log(JSON.stringify({ shadow_tail: true, logs: logPaths, out: logPaths.length ? outFile : null, offsets: logPaths.length ? offsetsPath : null, customer: Boolean(customer) }));
for (;;) {
  if (logPaths.length) await writeRow.trim();
  for (const p of logPaths) {
    try { await consume(p); } catch (e) { console.error('tail_error', p, e.message); }
  }
  await persistOffsets();
  if (customer) { try { await customer.poll(); } catch (e) { console.error('customer_tail_error', e.message); } }
  await new Promise(r => setTimeout(r, pollMs));
}
