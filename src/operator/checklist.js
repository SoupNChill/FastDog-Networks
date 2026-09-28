import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { ROOT } from '../lib/config.js';

const execFileAsync = promisify(execFile);
export const NS_HOLD = 'Registrar NS is on HOLD. This tool never flips nameservers.';

export function parseChecklist(stdout = '', error = null) {
  const lines = stdout.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const checks = lines.filter((line) => /^(PASS|FAIL)\b/.test(line));
  const safe = !error && checks.length > 0 && lines.includes('SAFE_TO_FLIP=yes') && !checks.some((line) => line.startsWith('FAIL'));
  return { SAFE_TO_FLIP: safe ? 'yes' : 'no', checks, lines, hold: NS_HOLD, ...(error ? { error: error.message } : {}) };
}

export async function runChecklist() {
  try {
    const { stdout } = await execFileAsync('bash', ['scripts/ns-cut-checklist.sh'], { cwd: ROOT, timeout: 15000, maxBuffer: 64 * 1024 });
    return parseChecklist(stdout);
  } catch (error) {
    // The script exits 1 for failed checks (including missing dig); retain its output.
    return parseChecklist(error.stdout || '', error);
  }
}
