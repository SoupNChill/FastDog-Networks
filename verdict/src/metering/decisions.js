import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

export const logPath = path => typeof path === 'string' ? path.split(/[?#]/, 1)[0].slice(0, 2048) : null;
export function createDecisionLog(file) {
  let pending = Promise.resolve();
  return record => {
    const { request_id, action, reason, engine, ip = null, path, key_id = null } = record;
    const line = JSON.stringify({ request_id, action, reason, engine, ip, path: logPath(path), key_id, ts: new Date().toISOString() }) + '\n';
    const task = pending.then(async () => {
      await mkdir(dirname(file), { recursive: true });
      await appendFile(file, line, { mode: 0o600 });
    });
    pending = task.catch(() => {});
    return task;
  };
}
