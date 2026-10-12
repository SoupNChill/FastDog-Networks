import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { ROOT, env } from '../lib/config.js';

export const dataDir = () => path.resolve(ROOT, env('DATA_DIR', 'data'));
const dataFile = (name, directory) => path.join(directory, name);

const revisions = new Map();
export const jsonRevision = (name, directory = dataDir()) => revisions.get(path.resolve(directory, name)) ?? 0;

export function readJson(name, fallback, directory = dataDir()) {
  const file = dataFile(name, directory);
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : fallback;
}

export function writeJson(name, data, mode = 0o644, directory = dataDir()) {
  fs.mkdirSync(directory, { recursive: true });
  const file = dataFile(name, directory);
  const temp = `${file}.${process.pid}.${randomUUID()}.tmp`;
  fs.writeFileSync(temp, `${JSON.stringify(data, null, 2)}\n`, { mode });
  fs.renameSync(temp, file);
  fs.chmodSync(file, mode);
  const key = path.resolve(file);
  revisions.set(key, (revisions.get(key) ?? 0) + 1);
}
