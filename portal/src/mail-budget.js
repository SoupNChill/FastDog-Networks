import { mkdirSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { acquireLock } from './mail-lock.js';
import { OWNER_KINDS } from './mail-templates.js';

// Exclusive directory lock serializes portal/CLI reservations. Fail closed on contention
// or damaged state; a lock left by a crash is broken after 30 s and logged as `lock_stuck`.
export function createMailBudget({ directory, mailbox, maxPerHour, now = Date.now, log }) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const key = createHash('sha256').update(mailbox).digest('hex');
  const file = join(directory, `${key}.json`), lock = `${file}.lock`;
  return (to, kind) => {
    const release = acquireLock(lock, { log });
    if (!release) return 'budget_unavailable';
    try {
      let entries = [];
      try { entries = JSON.parse(readFileSync(file, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
      if (!Array.isArray(entries) || entries.some((entry) => !entry || !Number.isFinite(entry.at) || typeof entry.recipient !== 'string')) throw new Error('Invalid budget');
      const current = now();
      entries = entries.filter((entry) => current - entry.at < 3600000);
      const recipient = createHash('sha256').update(to.toLowerCase()).digest('hex');
      if (entries.filter((entry) => entry.recipient === recipient).length >= 3) return 'recipient_cap';
      const reserved = maxPerHour >= 10 ? Math.ceil(maxPerHour / 10) : 0;
      // Owner notices only use the first 80% of the hour, so they never take capacity verification or reset mail needs.
      if (OWNER_KINDS.has(kind) && entries.length >= Math.floor(maxPerHour * 0.8)) return 'rate_cap';
      if (entries.length >= maxPerHour || (!['invite', 'password-reset'].includes(kind) && entries.length >= maxPerHour - reserved)) return 'rate_cap';
      entries.push({ at: current, recipient });
      writeFileSync(`${file}.tmp`, JSON.stringify(entries), { mode: 0o600 });
      renameSync(`${file}.tmp`, file);
      return null;
    } catch { return 'budget_unavailable'; }
    finally { release(); }
  };
}
