import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { ROOT, env } from '../lib/config.js';

export const dataDir = () => path.resolve(ROOT, env('DATA_DIR', 'data'));
export const dataFile = (name, directory) => path.join(directory, combined(directory) && AUTH_FILES.includes(name) ? STATE : name);

const revisions = new Map();
export const jsonRevision = (name, directory = dataDir()) => revisions.get(path.resolve(directory, name)) ?? 0;

export function readJson(name, fallback, directory = dataDir()) {
  if (combined(directory) && AUTH_FILES.includes(name)) return structuredClone(snapshot(directory)[name] ?? fallback);
  const file = dataFile(name, directory);
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : fallback;
}

export function writeJson(name, data, mode = 0o644, directory = dataDir()) {
  if (combined(directory) && AUTH_FILES.includes(name)) {
    return authTransaction(directory, () => {
      const current = transactions.get(path.resolve(directory));
      if (name === 'agent-credentials.json') for (const record of data) {
        const old = current[name]?.find((c) => c.id === record.id);
        if (old?.key_fingerprint !== undefined && old.key_fingerprint !== record.key_fingerprint) throw new Error('immutable_key_binding');
      }
      current[name] = structuredClone(data);
    });
  }
  fs.mkdirSync(directory, { recursive: true });
  const file = dataFile(name, directory);
  const temp = `${file}.${process.pid}.${randomUUID()}.tmp`;
  fs.writeFileSync(temp, `${JSON.stringify(data, null, 2)}\n`, { mode });
  fs.renameSync(temp, file);
  fs.chmodSync(file, mode);
  const key = path.resolve(file);
  revisions.set(key, (revisions.get(key) ?? 0) + 1);
}

// Synchronous transactions are the single process writer lock: callbacks must never yield.
const AUTH_FILES = ['agent-credentials.json', 'tenant_hostnames.json', 'agent-bootstrap.json'];
const enabled = new Set();
const transactions = new Map();
const STATE = 'agent-auth-state.json';
export const combined = (directory) => enabled.has(path.resolve(directory)) || fs.existsSync(path.join(directory, STATE));
function snapshot(directory) {
  const state = transactions.get(path.resolve(directory)) ?? JSON.parse(fs.readFileSync(path.join(directory, STATE), 'utf8'));
  if (state?.version !== 1 || !Array.isArray(state['agent-credentials.json']) || !Array.isArray(state['tenant_hostnames.json']) || !state['agent-bootstrap.json']) throw new Error('invalid_auth_snapshot');
  return state;
}
export function atomicSnapshot(file, value, beforeRename = () => {}) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.${randomUUID()}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify(value) + '\n');
    fs.fsyncSync(fd); fs.closeSync(fd); fd = undefined;
    beforeRename();
    fs.renameSync(temp, file);
    const dir = fs.openSync(path.dirname(file), 'r');
    try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(temp); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  }
}
export function enableAuthState(directory = dataDir()) {
  const file = path.join(directory, STATE);
  if (!fs.existsSync(file)) {
    fs.mkdirSync(directory, { recursive: true });
    const lock = path.join(directory, '.agent-auth.lock');
    const fd = fs.openSync(lock, 'wx', 0o600);
    try {
      if (!fs.existsSync(file)) {
        const initial = { version: 1 };
        for (const name of AUTH_FILES) initial[name] = readJson(name, [], directory);
        atomicSnapshot(file, initial);
      }
    } finally { fs.closeSync(fd); fs.unlinkSync(lock); }
  }
  snapshot(directory);
  enabled.add(path.resolve(directory));
}
export function authTransaction(directory, fn) {
  if (!combined(directory)) return fn();
  const key = path.resolve(directory);
  if (transactions.has(key)) return fn();
  const lock = path.join(directory, '.agent-auth.lock');
  let fd;
  try { fd = fs.openSync(lock, 'wx', 0o600); } catch { throw Object.assign(new Error('bootstrap_unavailable'), { status: 503, code: 'bootstrap_unavailable' }); }
  try { transactions.set(key, snapshot(directory)); } catch (e) { fs.closeSync(fd); fs.unlinkSync(lock); throw e; }
  try {
    const result = fn();
    if (result?.then) throw new Error('asynchronous_auth_transaction');
    const next = transactions.get(key);
    if (JSON.stringify(next) !== fs.readFileSync(path.join(directory, STATE), 'utf8').trim()) {
      atomicSnapshot(path.join(directory, STATE), next);
      for (const name of AUTH_FILES) { const file = path.resolve(directory, name); revisions.set(file, (revisions.get(file) ?? 0) + 1); }
    }
    return result;
  } finally { transactions.delete(key); fs.closeSync(fd); fs.unlinkSync(lock); }
}
