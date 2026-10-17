import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { dataDir } from '../onboard/json.js';
import { normalizeHostname } from '../onboard/hostname.js';

export const STATE_FILE = 'tls_ask_approvals.json';
export const validApproval = (e) => e && typeof e === 'object' && typeof e.host === 'string' && typeof e.domain === 'string'
  && (e.tenant === null || typeof e.tenant === 'string') && Number.isFinite(e.at);

// Both writers hold this lock across read/modify/atomic rename. Contention fails closed.
export function updateApprovals(directory, update) {
  fs.mkdirSync(directory, { recursive: true });
  const file = path.join(directory, STATE_FILE);
  const lock = `${file}.lock`;
  const fd = fs.openSync(lock, 'wx', 0o600);
  const temp = `${file}.${process.pid}.${randomUUID()}.tmp`;
  try {
    let list;
    try { list = JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch (error) { if (error.code !== 'ENOENT') throw error; list = []; }
    if (!Array.isArray(list) || !list.every(validApproval)) throw new Error('invalid approval state');
    const updated = update(list);
    fs.writeFileSync(temp, `${JSON.stringify(updated)}\n`, { mode: 0o600, flag: 'wx' });
    fs.renameSync(temp, file);
    return updated;
  } finally {
    try { fs.rmSync(temp, { force: true }); } catch { /* Best effort after a failed write. */ }
    fs.closeSync(fd);
    fs.unlinkSync(lock);
  }
}

export function resetTlsApprovals(hostname, directory = dataDir()) {
  const host = normalizeHostname(hostname);
  let removed = 0;
  updateApprovals(directory, list => list.filter(entry => {
    if (entry.host !== host) return true;
    removed++;
    return false;
  }));
  return { removed };
}
