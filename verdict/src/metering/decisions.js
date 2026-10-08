import { appendFile, mkdir, open, stat, truncate } from 'node:fs/promises';
import { dirname } from 'node:path';

export const logPath = path => typeof path === 'string' ? path.split(/[?#]/, 1)[0].slice(0, 2048) : null;
export function createDecisionLog(file, {
  maxBytes = Number(process.env.VERDICT_DECISION_MAX_BYTES ?? 5 * 1024 * 1024),
  maxAgeDays = Number(process.env.VERDICT_DECISION_MAX_AGE_DAYS ?? 7),
  now = Date.now,
} = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || !Number.isFinite(maxAgeDays) || maxAgeDays < 0) {
    throw new Error('Decision retention limits must be nonnegative; bytes must be a safe integer');
  }
  let pending = Promise.resolve();
  let size;
  let oldest;
  const append = record => {
    const task = pending.then(async () => {
      await mkdir(dirname(file), { recursive: true });
      if (size === undefined) {
        try {
          const info = await stat(file);
          size = info.size;
          // Read only the first bounded record, never the whole log.
          const handle = await open(file, 'r');
          try {
            const buffer = Buffer.alloc(16384);
            const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
            try { oldest = Date.parse(JSON.parse(buffer.toString('utf8', 0, bytesRead).split('\n')[0]).ts); }
            catch { oldest = NaN; }
          } finally { await handle.close(); }
          // Unknown timestamps are expired conservatively.
          if (!Number.isFinite(oldest)) oldest = 0;
        } catch (error) { if (error.code !== 'ENOENT') throw error; size = 0; }
      }
      const time = now();
      const { request_id, action, reason, engine, ip = null, path, key_id = null } = record;
      const line = JSON.stringify({ request_id, action, reason, engine, ip, path: logPath(path), key_id, ts: new Date(time).toISOString() }) + '\n';
      const bytes = Buffer.byteLength(line);
      if (size && ((maxBytes && size + bytes > maxBytes) || (maxAgeDays && time - oldest >= maxAgeDays * 86400000))) {
        await truncate(file, 0);
        size = 0;
      }
      // A single oversized record cannot violate the configured disk ceiling.
      if (maxBytes && bytes > maxBytes) return;
      await appendFile(file, line, { mode: 0o600 });
      if (!size) oldest = time;
      size += bytes;
    });
    pending = task.catch(() => { size = undefined; });
    return task;
  };
  append.ready = () => pending;
  return append;
}
