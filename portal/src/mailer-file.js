import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
export function createFileMailer({ outboxDir }) {
  if (!outboxDir) throw new Error('Outbox directory required');
  mkdirSync(outboxDir, { recursive: true, mode: 0o700 });
  return {
    async send({ to, kind, link }) {
      writeFileSync(join(outboxDir, `${randomUUID()}.json`), `${JSON.stringify({ to, kind, link })}\n`, { mode: 0o600, flag: 'wx' });
    },
  };
}
