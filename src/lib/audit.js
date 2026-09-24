import fs from 'node:fs';
import path from 'node:path';
import { ROOT, env } from './config.js';

function auditPath() {
  const configured = env('COREDNS_AUDIT_LOG', '');
  if (configured) return path.isAbsolute(configured) ? configured : path.join(ROOT, configured);
  const dataDir = env('DATA_DIR', path.join(ROOT, 'data'));
  const absData = path.isAbsolute(dataDir) ? dataDir : path.join(ROOT, dataDir);
  return path.join(absData, 'audit', 'coredns-sync.jsonl');
}

/** Append one structured JSONL audit event. Never throws to callers. */
export function appendAudit(event = {}) {
  const file = auditPath();
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    ...event,
  });
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o750 });
    fs.appendFileSync(file, line + '\n', { mode: 0o640 });
    try { fs.chmodSync(file, 0o640); } catch { /* best-effort */ }
    return { ok: true, path: file };
  } catch (error) {
    return { ok: false, path: file, error: error.message };
  }
}

export function auditLogPath() {
  return auditPath();
}