import { mkdirSync, readFileSync, writeFileSync, renameSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

export function createStore(dataDir) {
  if (!dataDir) throw new Error('State directory required');
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  return {
    read(name, fallback) {
      try { return JSON.parse(readFileSync(join(dataDir, `${name}.json`), 'utf8')); }
      catch (error) { if (error.code === 'ENOENT') return structuredClone(fallback); throw error; }
    },
    write(name, value) {
      const file = join(dataDir, `${name}.json`);
      const temporary = `${file}.${randomUUID()}.tmp`;
      try {
        writeFileSync(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600, flag: 'wx' });
        renameSync(temporary, file);
      } finally { rmSync(temporary, { force: true }); }
    },
  };
}
export const emptyAccounts = () => ({ users: [], tenants: [], invites: [], links: [] });
