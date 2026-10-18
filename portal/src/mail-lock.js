import { mkdirSync, statSync, renameSync, rmdirSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

export const STALE_LOCK_MS = 30000;
const sleeper = new Int32Array(new SharedArrayBuffer(4));
// Exclusive directory lock; returns a release function, or null while another writer holds it.
// A lock older than STALE_LOCK_MS (crash or SIGKILL) is moved aside and removed only if the moved
// directory is still the stale one, then logged with reason `lock_stuck`. Uses wall-clock time
// because lock mtimes are wall-clock.
export function acquireLock(path, { log = () => {}, staleMs = STALE_LOCK_MS } = {}) {
  const release = () => { try { rmdirSync(path); } catch { /* already gone */ } };
  for (let attempt = 0; attempt < 4; attempt++) {
    if (attempt) Atomics.wait(sleeper, 0, 0, 10);
    try { mkdirSync(path, { mode: 0o700 }); return release; } catch (error) { if (error.code !== 'EEXIST') return null; }
    let stale;
    try { stale = statSync(path); } catch { continue; }
    if (Date.now() - stale.mtimeMs <= staleMs) continue;
    const aside = `${path}.stale-${randomUUID()}`;
    try { renameSync(path, aside); } catch { continue; }
    try {
      if (statSync(aside).ino !== stale.ino) { try { renameSync(aside, path); } catch { /* best effort */ } return null; }
      rmdirSync(aside);
    } catch { return null; }
    try { log('lock_stuck'); } catch { /* logging must not break mail */ }
  }
  return null;
}
