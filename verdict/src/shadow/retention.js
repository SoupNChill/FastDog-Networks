import { appendFile, mkdir, readFile, readdir, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';

const DAY = 86400000;
export function shadowRetentionDays(env = process.env) {
  const raw = env.VERDICT_SHADOW_MAX_AGE_DAYS ?? env.SHADOW_RETENTION_DAYS;
  const days = raw === undefined || String(raw).trim() === '' ? NaN : Number(raw);
  return Number.isFinite(days) ? Math.max(7, days) : 30;
}
const warnDefault = code => console.warn('shadow_retention_warning', code);

export function createShadowWriter(file, {
  maxAgeDays = shadowRetentionDays(),
  maxBytes = Number(process.env.VERDICT_SHADOW_MAX_BYTES ?? 10 * 1024 * 1024),
  now = Date.now,
  warn = warnDefault,
} = {}) {
  const days = shadowRetentionDays({ VERDICT_SHADOW_MAX_AGE_DAYS: maxAgeDays });
  const cap = Number.isSafeInteger(maxBytes) && maxBytes >= 0 ? maxBytes : 10 * 1024 * 1024;
  let pending = Promise.resolve();
  let nextCheck = 0;
  const report = error => { try { warn(error.code || 'IO_ERROR'); } catch {} };
  const enqueue = fn => {
    const task = pending.then(fn).catch(report);
    pending = task;
    return task;
  };
  async function trim(reserve = 0, incoming) {
    const time = now();
    let info;
    try { info = await stat(file); } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
    if (time < nextCheck && (!cap || info.size + reserve <= cap)) return;
    let includeIncoming = false;
    try {
      const original = await readFile(file, 'utf8');
      const rows = [];
      for (const line of original.split('\n')) {
        if (!line) continue;
        let ts;
        try { ts = Date.parse(JSON.parse(line).ts); } catch { continue; }
        // Undated or corrupt records cannot establish a retention age: discard them.
        if (Number.isFinite(ts) && ts > time - days * DAY) rows.push({ line: line + '\n', ts });
      }
      includeIncoming = Boolean(incoming && cap && info.size + reserve > cap);
      if (includeIncoming) {
        rows.push({ line: incoming, ts: Date.parse(JSON.parse(incoming).ts) });
        reserve = 0;
      }
      let bytes = rows.reduce((sum, row) => sum + Buffer.byteLength(row.line), 0);
      // Age comes first. The disk cap takes priority over the seven-day age floor
      // only when necessary; remove oldest timestamps, even in out-of-order logs.
      const removed = new Set();
      if (cap && bytes + reserve > cap) {
        for (const row of [...rows].sort((a, b) => a.ts - b.ts)) {
          if (bytes + reserve <= cap) break;
          removed.add(row);
          bytes -= Buffer.byteLength(row.line);
        }
      }
      const kept = rows.filter(row => !removed.has(row)).map(row => row.line).join('');
      if (kept !== original) {
        const temp = `${file}.${randomUUID()}.tmp`;
        try {
          await writeFile(temp, kept, { flag: 'wx', mode: 0o600 });
          await rename(temp, file);
        } finally {
          await unlink(temp).catch(error => { if (error.code !== 'ENOENT') report(error); });
        }
      }
    } finally {
      // Always backoff, including on failure, so a sticky EACCES/ENOSPC does not
      // re-read up to 10 MiB on every append.
      nextCheck = time + 60000;
    }
    return includeIncoming;
  }
  const append = record => enqueue(async () => {
    await mkdir(dirname(file), { recursive: true });
    const line = JSON.stringify(record) + '\n';
    const bytes = Buffer.byteLength(line);
    const ts = Date.parse(record.ts);
    // Skip oversized/expired incoming records without evicting useful history.
    if (!Number.isFinite(ts) || ts <= now() - days * DAY || (cap && bytes > cap)) {
      await trim();
      return;
    }
    try { if (await trim(bytes, line)) return; } catch (error) { report(error); }
    await appendFile(file, line, { mode: 0o600 });
  });
  append.trim = () => enqueue(() => trim());
  append.ready = () => pending;
  return append;
}

export async function pruneShadowSummaries(dir, { maxAgeDays = shadowRetentionDays(), now = Date.now, warn = warnDefault } = {}) {
  const cutoff = now() - shadowRetentionDays({ VERDICT_SHADOW_MAX_AGE_DAYS: maxAgeDays }) * DAY;
  const report = error => { try { warn(error.code || 'IO_ERROR'); } catch {} };
  try {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const match = /^shadow-summary-(\d{4})(\d{2})(\d{2})\.json$/.exec(entry.name);
      if (!entry.isFile() || !match) continue;
      const date = `${match[1]}-${match[2]}-${match[3]}`;
      const ts = Date.parse(date);
      if (!Number.isFinite(ts) || new Date(ts).toISOString().slice(0, 10) !== date) continue;
      if (ts <= cutoff) {
        try { await unlink(join(dir, entry.name)); } catch (error) { report(error); }
      }
    }
  } catch (error) { report(error); }
}
