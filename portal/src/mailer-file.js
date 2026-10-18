import { mkdirSync, writeFileSync, readdirSync, lstatSync, unlinkSync, rmdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
export const OUTBOX_TTL_MS = 7 * 24 * 3600 * 1000;
export function createFileMailer({ outboxDir, maxFiles = 10000 }) {
  if (!outboxDir) throw new Error('Outbox directory required');
  mkdirSync(outboxDir, { recursive: true, mode: 0o700 });
  return {
    outboxDir,
    // `code` (invites) and `status` (SMTP fallback/redacted copy) are optional and omitted when unset.
    async send({ to, kind, link, code, status }) {
      const lock = join(outboxDir, '.write-lock');
      mkdirSync(lock, { mode: 0o700 });
      try {
        if (readdirSync(outboxDir).filter((name) => name.endsWith('.json')).length >= maxFiles) throw new Error('Outbox full');
        writeFileSync(join(outboxDir, `${randomUUID()}.json`), `${JSON.stringify({ to, kind, link, code, status })}\n`, { mode: 0o600, flag: 'wx' });
        return { delivered: 'outbox' };
      } finally { rmdirSync(lock); }
    },
  };
}
// Deletes regular outbox message files older than the TTL; returns the count removed.
export function purgeOutbox(outboxDir, now = Date.now(), ttlMs = OUTBOX_TTL_MS) {
  let removed = 0;
  let names;
  try { names = readdirSync(outboxDir); } catch { return 0; }
  for (const name of names.filter((item) => item.endsWith('.json'))) {
    const path = join(outboxDir, name);
    try {
      const stat = lstatSync(path);
      if (stat.isFile() && now - stat.mtimeMs > ttlMs) { unlinkSync(path); removed++; }
    } catch { /* raced with another cleanup; ignore */ }
  }
  return removed;
}

export function scheduleOutboxPurge(outboxDir, schedule = setInterval) {
  purgeOutbox(outboxDir);
  const timer = schedule(() => purgeOutbox(outboxDir), 3600000);
  timer.unref();
  return timer;
}
