import fs from 'node:fs/promises';
import path from 'node:path';
import { env, ROOT } from '../lib/config.js';

export function statusFile() {
  const dir = env('DATA_DIR', path.join(ROOT, 'data'));
  return path.join(path.isAbsolute(dir) ? dir : path.join(ROOT, dir), 'status.json');
}

export async function readStatus(file = statusFile()) {
  try {
    const value = JSON.parse(await fs.readFile(file, 'utf8'));
    return value && Array.isArray(value.checks) && !Number.isNaN(Date.parse(value.lastChecked)) ? value : null;
  } catch (error) {
    if (error.code !== 'ENOENT') console.warn(`status: could not read ${file}: ${error.message}`);
    return null;
  }
}

export async function writeStatus(value, file = statusFile()) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  try {
    await fs.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    await fs.rename(temporary, file);
  } catch (error) {
    await fs.rm(temporary, { force: true });
    throw error;
  }
}
